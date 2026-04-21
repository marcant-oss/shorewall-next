"""Native nftables integration via libnftables, JSON API, and pyroute2.

Provides direct interaction with the kernel nftables subsystem:
- Atomic ruleset replacement (no flush+load race)
- Live counter/set queries without spawning processes
- Set element manipulation (dynamic blacklist)
- Dry-run validation (nft -c)
- Native network namespace support via fork+setns — no subprocess needed

Priority: libnftables (C bindings) > nft subprocess text.
For netns: fork → child enters netns via setns() → child opens libnftables
→ child does the work → child returns result via IPC → parent reaps child.
This avoids re-binding cached netlink sockets (which setns() cannot do).
"""

from __future__ import annotations

import contextlib
import ctypes
import ctypes.util
import json
import os
import subprocess
from pathlib import Path
from typing import Any

from shorewall_nft_netkit.netns_fork import run_in_netns_fork

# nft binary path — search common locations (for fallback path only)
_NFT_PATHS = ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"]

# setns(2) flag for the network namespace
_CLONE_NEWNET = 0x40000000

_libc_ns: "ctypes.CDLL | None" = None


def _libc() -> ctypes.CDLL:
    global _libc_ns
    if _libc_ns is None:
        _libc_ns = ctypes.CDLL(
            ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
    return _libc_ns


def _find_nft() -> str:
    """Find the nft binary (fallback path only)."""
    for p in _NFT_PATHS:
        if Path(p).exists():
            return p
    return "nft"


class NftError(Exception):
    """Error from nft operation."""


# ---------------------------------------------------------------------------
# Module-level helpers for run_in_netns_fork (must be pickleable)
# ---------------------------------------------------------------------------


def _libnftables_cmd_in_child(
    script: str, *, check_only: bool = False
) -> tuple[int, str, str]:
    """Run a libnftables command in the child process (must be module-level
    for pickle compatibility).  Called via run_in_netns_fork.
    """
    try:
        import nftables as _nft_mod
    except ImportError:
        import sys
        sys.path.insert(0, "/usr/lib/python3/dist-packages")
        import nftables as _nft_mod
    nft = _nft_mod.Nftables()
    nft.set_json_output(True)
    nft.set_handle_output(True)
    if check_only:
        try:
            nft.set_dry_run(True)
        except AttributeError:
            pass  # older libnftables without set_dry_run
    rc, out, err = nft.cmd(script)
    return (rc, out or "", err or "")


def _invoke_subprocess(
    args: list[str], **kwargs
) -> tuple[int, bytes | str | None, bytes | str | None]:
    """Run a subprocess in the child process and return a serialisable tuple.

    Returns (returncode, stdout, stderr) — safe to pickle.
    """
    result = subprocess.run(args, **kwargs)  # noqa: S603
    return (result.returncode, result.stdout, result.stderr)


@contextlib.contextmanager
def _in_netns(name: str | None):
    """Context manager that enters a named network namespace.

    Saves the current net namespace fd, opens ``/run/netns/<name>``,
    calls ``setns()`` into it, yields, then restores the original
    namespace on exit. ``name=None`` is a no-op.

    Raises ``OSError`` if setns fails (typically EPERM for non-root
    callers); the caller is expected to fall back to the subprocess
    wrapper path in that case.
    """
    if not name:
        yield
        return
    target_path = f"/run/netns/{name}"
    if not Path(target_path).exists():
        raise OSError(2, f"netns {name!r} not found at {target_path}")
    saved_fd = os.open("/proc/self/ns/net", os.O_RDONLY)
    try:
        target_fd = os.open(target_path, os.O_RDONLY)
        try:
            rc = _libc().setns(target_fd, _CLONE_NEWNET)
            if rc != 0:
                err = ctypes.get_errno()
                raise OSError(err,
                              f"setns({name}): {os.strerror(err)}")
            yield
        finally:
            os.close(target_fd)
    finally:
        # Always restore, even if the body raised.
        try:
            _libc().setns(saved_fd, _CLONE_NEWNET)
        finally:
            os.close(saved_fd)


class NftInterface:
    """Interface to nftables — uses libnftables if available, subprocess otherwise.

    All methods that take ``netns=`` run in the current namespace when
    netns is None (libnftables in-process).  When netns is given,
    ``run_in_netns_fork`` forks a child that enters the target namespace
    before opening a fresh libnftables handle — cached sockets cannot be
    moved via setns, so the fork is the only correct approach.
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

    # ── core dispatch ────────────────────────────────────────────────

    def _run_text(self, nft_text: str, *,
                  netns: str | None = None) -> dict[str, Any]:
        """Run one or more nft text commands, return JSON dict.

        Uses libnftables in-process when netns is None (current namespace).
        When netns is given, delegates to ``_subprocess_text`` which uses
        ``run_in_netns_fork``: libnftables caches its netlink socket on first
        use; the fork enters the target namespace before opening any sockets,
        which is the only safe way to reach a different netns.
        """
        if self._use_lib and netns is None:
            rc, output, error = self._nft.cmd(nft_text)
            if rc != 0:
                raise NftError(f"nft: {error}")
            return json.loads(output) if output else {}
        return self._subprocess_text(nft_text, netns=netns)

    def _subprocess_text(self, nft_text: str, *,
                         netns: str | None = None) -> dict[str, Any]:
        """Run nft via subprocess with JSON output (fallback path).

        When netns is set, uses run_in_netns_fork so the child opens a fresh
        libnftables handle after entering the target namespace.  When netns is
        None the nft binary is invoked directly (no libnftables available on
        this path).
        """
        if netns:
            rc, out, _err = run_in_netns_fork(
                netns, _libnftables_cmd_in_child, nft_text
            )
            if rc != 0:
                raise NftError(f"nft: {_err.strip()}")
            return json.loads(out) if out else {}
        cmd = [self._nft_bin, "-j", nft_text]
        result = subprocess.run(cmd, capture_output=True, text=True)  # noqa: S603
        if result.returncode != 0:
            raise NftError(f"nft: {result.stderr.strip()}")
        return json.loads(result.stdout) if result.stdout else {}

    def cmd(self, command: str, *,
            netns: str | None = None) -> dict[str, Any]:
        """Run an nft command and return JSON output."""
        return self._run_text(command, netns=netns)

    def cmd_json(self, json_payload: dict) -> dict[str, Any]:
        """Send a JSON command directly to nft (library path only)."""
        if self._use_lib:
            self._nft.set_json_output(True)
            rc, output, error = self._nft.json_cmd(json_payload)
            if rc != 0:
                raise NftError(f"nft json: {error}")
            return json.loads(output) if output else {}
        payload_str = json.dumps(json_payload)
        result = subprocess.run(
            [self._nft_bin, "-j", "-f", "-"],
            input=payload_str, capture_output=True, text=True
        )
        if result.returncode != 0:
            raise NftError(f"nft: {result.stderr.strip()}")
        return json.loads(result.stdout) if result.stdout else {}

    # ── high-level ops ──────────────────────────────────────────────

    def load_file(self, path: str | Path, *, check_only: bool = False,
                  netns: str | None = None) -> None:
        """Load an nft script file atomically.

        Uses libnftables in-process when netns is None (current namespace).
        Falls back to subprocess for a different netns (see _run_text comment).
        """
        if self._use_lib and netns is None:
            script = Path(path).read_text()
            try:
                if check_only:
                    self._nft.set_dry_run(True)
                try:
                    rc, _output, error = self._nft.cmd(script)
                finally:
                    if check_only:
                        self._nft.set_dry_run(False)
            except AttributeError:
                # older libnftables without set_dry_run
                if not check_only:
                    raise
            else:
                if rc != 0:
                    raise NftError(f"nft -f{'c' if check_only else ''}: {error}")
                return
        if netns:
            # Pass the script text to the child — avoids a TOCTOU race on the
            # path and works even if the child doesn't share the filesystem.
            script = Path(path).read_text()
            rc, _out, err = run_in_netns_fork(
                netns, _libnftables_cmd_in_child, script, check_only=check_only
            )
            if rc != 0:
                raise NftError(f"nft -f{'c' if check_only else ''}: {err.strip()}")
            return
        cmd = [self._nft_bin]
        if check_only:
            cmd.append("-c")
        cmd.extend(["-f", str(path)])
        result = subprocess.run(cmd, capture_output=True, text=True)  # noqa: S603
        if result.returncode != 0:
            raise NftError(f"nft -f: {result.stderr.strip()}")

    def validate(self, script: str, *, netns: str | None = None) -> bool:
        """Validate an nft script without applying it (dry-run)."""
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".nft",
                                         delete=False) as f:
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
        try:
            return self._run_text(f"list table {family} {table}", netns=netns)
        except NftError as e:
            raise NftError(f"Table not found: {family} {table}") from e

    def list_counters(self, family: str = "inet", table: str = "shorewall",
                      *, netns: str | None = None) -> dict[str, dict[str, int]]:
        """List all counter values. Returns {name: {packets: N, bytes: N}}."""
        try:
            data = self._run_text(
                f"list counters table {family} {table}", netns=netns)
        except NftError:
            return {}
        counters: dict[str, dict[str, int]] = {}
        for item in data.get("nftables", []):
            if "counter" in item:
                c = item["counter"]
                counters[c.get("name", "")] = {
                    "packets": c.get("packets", 0),
                    "bytes": c.get("bytes", 0),
                }
        return counters

    def list_rule_counters(self, family: str = "inet", table: str = "shorewall",
                           *, netns: str | None = None) -> list[dict[str, Any]]:
        """Walk a table's ruleset and yield every rule's inline counter.

        Unlike :meth:`list_counters` (which only returns named counter
        objects, i.e. the ``nfacct``-style ones), this extracts the
        ``counter`` expression that nft emits inside every rule when
        the compiler asks for per-rule accounting.

        Single libnftables round-trip: ``list table <fam> <table>``
        returns the entire ruleset JSON in one dump, and we walk it
        once to extract rule counters. Used by the shorewalld
        Prometheus exporter — the per-scrape cost is one netlink
        dump per netns, well under the 50 ms budget even at 1600+
        rules.

        Returns a list of dicts with keys ``table``, ``chain``,
        ``handle``, ``comment``, ``packets``, ``bytes``. Missing
        fields default to empty string / zero.
        """
        try:
            data = self.list_table(family=family, table=table, netns=netns)
        except NftError:
            return []
        out: list[dict[str, Any]] = []
        for item in data.get("nftables", []):
            rule = item.get("rule")
            if not rule:
                continue
            packets = 0
            bytes_ = 0
            found = False
            for expr in rule.get("expr", []):
                c = expr.get("counter") if isinstance(expr, dict) else None
                if isinstance(c, dict):
                    packets += int(c.get("packets", 0))
                    bytes_ += int(c.get("bytes", 0))
                    found = True
            if not found:
                continue
            out.append({
                "table": rule.get("table", table),
                "chain": rule.get("chain", ""),
                "handle": rule.get("handle", 0),
                "comment": rule.get("comment", ""),
                "packets": packets,
                "bytes": bytes_,
            })
        return out

    def list_set_elements(self, set_name: str, family: str = "inet",
                          table: str = "shorewall",
                          *, netns: str | None = None) -> list[str]:
        """List elements of a named set."""
        try:
            data = self._run_text(
                f"list set {family} {table} {set_name}", netns=netns)
        except NftError:
            return []
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
        cmd = (f"add element {family} {table} {set_name} "
               f"{{ {element}{timeout_str} }}")
        try:
            self._run_text(cmd, netns=netns)
        except NftError as e:
            raise NftError(f"Failed to add element: {e}") from e

    def delete_set_element(self, set_name: str, element: str,
                           family: str = "inet", table: str = "shorewall",
                           *, netns: str | None = None) -> None:
        """Remove an element from a named set."""
        cmd = f"delete element {family} {table} {set_name} {{ {element} }}"
        try:
            self._run_text(cmd, netns=netns)
        except NftError as e:
            raise NftError(f"Failed to delete element: {e}") from e

    def run_in_netns(self, args: list[str], *,
                     netns: str | None = None,
                     **kwargs) -> "subprocess.CompletedProcess[str]":
        """Run a subprocess, entering *netns* via in-process setns() if provided.

        Primary path: uses ``_in_netns()`` context manager so the forked
        subprocess child inherits the target namespace without a privilege
        round-trip.  EPERM fallback: uses ``run_in_netns_fork`` with
        ``_invoke_subprocess`` — a child that enters the namespace first and
        then spawns the subprocess from within it.

        ``netns=None`` runs the command in the current namespace unchanged.
        Pass ``capture_output=True, text=True`` in *kwargs* as needed.
        """
        if netns:
            try:
                with _in_netns(netns):
                    return subprocess.run(args, **kwargs)  # noqa: S603
            except OSError:
                # EPERM: cannot setns in the parent — fork a child that enters
                # the netns before running the subprocess.
                rc, stdout, stderr = run_in_netns_fork(
                    netns, _invoke_subprocess, list(args), **kwargs
                )
                # Reconstruct a CompletedProcess from the serialised tuple.
                return subprocess.CompletedProcess(
                    args=list(args),
                    returncode=rc,
                    stdout=stdout,
                    stderr=stderr,
                )
        return subprocess.run(args, **kwargs)  # noqa: S603

    # ── back-compat alias for callers still using _subprocess_cmd ───

    def _subprocess_cmd(self, command: str) -> dict[str, Any]:
        """Compat alias — prefer :meth:`cmd` in new code."""
        return self._subprocess_text(command)
