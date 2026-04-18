"""nftables capability detection via runtime probing.

Discovers which nft features are available on the running kernel
by creating a temporary table and testing each feature. This makes
shorewall-nft automatically adapt to different kernel versions
and nft builds.

Usage:
    caps = NftCapabilities.probe(netns="shorewall-next-sim-probe")
    if caps.has_flowtable:
        emit_flowtable(...)
    if caps.has_synproxy:
        emit_synproxy(...)
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

_PROBE_TABLE = "__swnft_probe"


def _make_runner(nft: "NftInterface", netns: str | None):
    """Return (cmd_fn, probe_rule_fn) bound to *nft* and *netns*.

    ``cmd_fn(text) -> bool`` — True on success, False on any error.
    ``probe_rule_fn(rule) -> bool`` — add a rule to the test chain and
    flush it; True if the kernel accepted the syntax.

    All nft operations go through :class:`NftInterface` which prefers
    in-process ``setns()`` + libnftables and falls back to the
    ``sudo run-netns`` subprocess path only when ``setns()`` is denied.
    """
    from shorewall_nft.nft.netlink import NftError

    def _cmd(text: str) -> bool:
        try:
            nft._run_text(text, netns=netns)
            return True
        except (NftError, Exception):
            return False

    def _probe_rule(rule: str) -> bool:
        ok = _cmd(f"add rule inet {_PROBE_TABLE} __test {rule}")
        if ok:
            _cmd(f"flush chain inet {_PROBE_TABLE} __test")
        return ok

    return _cmd, _probe_rule


@dataclass
class NftCapabilities:
    """Detected nftables capabilities."""
    libnft_path: str = ""

    # Table families
    families: list[str] = field(default_factory=list)

    # Chain types + hooks
    chain_hooks: dict[str, list[str]] = field(default_factory=dict)

    # Match expressions
    has_ct_state: bool = False
    has_ct_helper: bool = False
    has_ct_count: bool = False
    has_fib: bool = False
    has_meta_nfproto: bool = False
    has_socket: bool = False
    has_tproxy: bool = False
    has_synproxy: bool = False
    has_osf: bool = False
    has_numgen: bool = False

    # Statements
    has_limit: bool = False
    has_quota: bool = False
    has_counter: bool = False
    has_log: bool = False
    has_notrack: bool = False
    has_nat: bool = False
    has_masquerade: bool = False
    has_redirect: bool = False
    has_tproxy_stmt: bool = False
    has_synproxy_stmt: bool = False
    has_flow_offload: bool = False
    has_queue: bool = False
    has_dup: bool = False
    has_fwd: bool = False

    # Set features
    has_interval_sets: bool = False
    has_timeout_sets: bool = False
    has_concat_sets: bool = False

    # Objects
    has_ct_helper_obj: bool = False
    has_ct_timeout_obj: bool = False
    has_synproxy_obj: bool = False
    has_counter_obj: bool = False
    has_quota_obj: bool = False
    has_limit_obj: bool = False
    has_secmark_obj: bool = False

    # Flowtable
    has_flowtable: bool = False
    has_flowtable_offload: bool = False  # software + HW fastpath

    # Kernel modules
    kernel_modules: list[str] = field(default_factory=list)

    @classmethod
    def probe(cls, netns: str | None = None,
              nft: "NftInterface | None" = None) -> "NftCapabilities":
        """Probe the running kernel for nft capabilities.

        All nft operations go through *nft* (:class:`NftInterface`).
        When *nft* is ``None`` a fresh instance is created.  The
        interface prefers in-process ``setns()`` + libnftables and
        falls back to ``sudo run-netns`` only when ``setns()`` is
        denied — so production systems (root + python3-nftables)
        never spawn a subprocess for namespace entry.
        """
        from shorewall_nft.nft.netlink import NftInterface as _NftInterface
        if nft is None:
            nft = _NftInterface()

        _cmd, _probe_rule = _make_runner(nft, netns)
        caps = cls()

        # Record which libnftables binary backs this NftInterface instance.
        caps.libnft_path = nft._nft_bin

        # Create probe table + filter chain.
        _cmd(f"add table inet {_PROBE_TABLE}")
        _cmd(f"add chain inet {_PROBE_TABLE} __test "
             f"{{ type filter hook input priority 0; }}")

        # Families
        for fam in ("ip", "ip6", "inet", "arp", "bridge", "netdev"):
            if _cmd(f"add table {fam} {_PROBE_TABLE}_fam"):
                caps.families.append(fam)
                _cmd(f"delete table {fam} {_PROBE_TABLE}_fam")

        # Chain type / hook combinations
        for chain_type in ("filter", "nat", "route"):
            hooks = []
            for hook in ("prerouting", "input", "forward", "output",
                         "postrouting", "ingress"):
                if _cmd(f"add chain inet {_PROBE_TABLE} __hook "
                        f"{{ type {chain_type} hook {hook} priority 0; }}"):
                    hooks.append(hook)
                    _cmd(f"delete chain inet {_PROBE_TABLE} __hook")
            caps.chain_hooks[chain_type] = hooks

        # Match expressions
        caps.has_ct_state      = _probe_rule("ct state established accept")
        caps.has_ct_helper     = _probe_rule('ct helper "ftp" accept')
        caps.has_ct_count      = _probe_rule("ct count 10 accept")
        caps.has_fib           = _probe_rule("fib daddr type local accept")
        caps.has_meta_nfproto  = _probe_rule("meta nfproto ipv4 accept")
        caps.has_socket        = _probe_rule("socket transparent 1 accept")
        caps.has_osf           = _probe_rule('osf name "Linux" accept')

        # Statements
        caps.has_limit   = _probe_rule("limit rate 10/second accept")
        caps.has_quota   = _probe_rule("quota over 1 mbytes drop")
        caps.has_counter = _probe_rule("counter accept")
        caps.has_log     = _probe_rule('log prefix "test" accept')
        caps.has_notrack = _probe_rule("notrack")

        # NAT: masquerade only valid in a nat-type chain.
        _cmd(f"add chain inet {_PROBE_TABLE} __nat_test "
             f"{{ type nat hook postrouting priority 100; }}")
        caps.has_nat = _cmd(
            f"add rule inet {_PROBE_TABLE} __nat_test masquerade")
        _cmd(f"flush chain inet {_PROBE_TABLE} __nat_test")
        _cmd(f"delete chain inet {_PROBE_TABLE} __nat_test")

        # Set features
        caps.has_interval_sets = _cmd(
            f"add set inet {_PROBE_TABLE} __s1 "
            f"{{ type ipv4_addr; flags interval; }}")
        _cmd(f"delete set inet {_PROBE_TABLE} __s1")

        caps.has_timeout_sets = _cmd(
            f"add set inet {_PROBE_TABLE} __s2 "
            f"{{ type ipv4_addr; flags timeout; }}")
        _cmd(f"delete set inet {_PROBE_TABLE} __s2")

        caps.has_concat_sets = _cmd(
            f"add set inet {_PROBE_TABLE} __s3 "
            f"{{ type ipv4_addr . inet_service; }}")
        _cmd(f"delete set inet {_PROBE_TABLE} __s3")

        # Objects
        caps.has_ct_helper_obj = _cmd(
            f'add ct helper inet {_PROBE_TABLE} __h '
            f'{{ type "ftp" protocol tcp; l3proto inet; }}')
        if caps.has_ct_helper_obj:
            _cmd(f"delete ct helper inet {_PROBE_TABLE} __h")

        caps.has_counter_obj = _cmd(
            f"add counter inet {_PROBE_TABLE} __c")
        if caps.has_counter_obj:
            _cmd(f"delete counter inet {_PROBE_TABLE} __c")

        caps.has_quota_obj = _cmd(
            f"add quota inet {_PROBE_TABLE} __q {{ over 1 mbytes }}")
        if caps.has_quota_obj:
            _cmd(f"delete quota inet {_PROBE_TABLE} __q")

        # Flowtable
        caps.has_flowtable = _cmd(
            f"add flowtable inet {_PROBE_TABLE} __ft "
            f"{{ hook ingress priority 0; devices = {{}}; }}")
        if caps.has_flowtable:
            _cmd(f"delete flowtable inet {_PROBE_TABLE} __ft")

        # Flowtable offload flag (kernel accepts the flag even without HW
        # support; actual HW offload is validated at packet time).
        caps.has_flowtable_offload = _cmd(
            f"add flowtable inet {_PROBE_TABLE} __ft2 "
            f"{{ hook ingress priority 0; devices = {{}}; flags offload; }}")
        if caps.has_flowtable_offload:
            _cmd(f"delete flowtable inet {_PROBE_TABLE} __ft2")

        # Kernel modules — host-global, no netns involved.
        import os
        uname = os.uname().release
        mod_dir = Path(f"/lib/modules/{uname}/kernel/net/netfilter")
        if mod_dir.exists():
            caps.kernel_modules = sorted(
                f.stem.replace("nft_", "")
                for f in mod_dir.glob("nft_*.ko*")
            )

        # Best-effort modprobe for essential modules (requires root).
        _essential_modules = [
            "nft_ct", "nft_log", "nft_limit", "nft_nat",
            "nft_masq", "nft_redir", "nft_quota", "nft_hash",
            "nft_numgen", "nft_fib", "nft_fib_inet",
            "nft_connlimit", "nft_flow_offload", "nft_osf",
        ]
        for mod in _essential_modules:
            if mod.replace("nft_", "") in caps.kernel_modules:
                try:
                    subprocess.run(
                        ["modprobe", mod], capture_output=True, timeout=5)
                except Exception:
                    pass

        # Cleanup probe table.
        _cmd(f"delete table inet {_PROBE_TABLE}")

        return caps

    def summary(self) -> str:
        """Human-readable summary of capabilities."""
        lines = [f"nftables  (libnftables, path: {self.libnft_path or 'unknown'})"]
        lines.append(f"Families: {', '.join(self.families)}")
        for ct, hooks in self.chain_hooks.items():
            lines.append(f"  {ct}: {', '.join(hooks)}")

        features = []
        for attr in sorted(dir(self)):
            if attr.startswith("has_") and getattr(self, attr):
                features.append(attr[4:])
        lines.append(f"Features ({len(features)}): {', '.join(features)}")
        lines.append(f"Kernel modules ({len(self.kernel_modules)}): {', '.join(self.kernel_modules[:10])}...")
        return "\n".join(lines)

    def check_rule_support(self, rule_str: str,
                           netns: str | None = None,
                           nft: "NftInterface | None" = None) -> bool:
        """Check whether a specific nft rule syntax is accepted by the kernel."""
        from shorewall_nft.nft.netlink import NftInterface as _NftInterface
        if nft is None:
            nft = _NftInterface()
        _cmd, _probe_rule = _make_runner(nft, netns)
        _cmd(f"add table inet {_PROBE_TABLE}")
        _cmd(f"add chain inet {_PROBE_TABLE} __test "
             f"{{ type filter hook input priority 0; }}")
        result = _probe_rule(rule_str)
        _cmd(f"delete table inet {_PROBE_TABLE}")
        return result
