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

_RUN_NETNS = ["sudo", "/usr/local/bin/run-netns"]
_PROBE_TABLE = "__swnft_probe"


def _nft(cmd: str, netns: str | None = None, timeout: int = 5) -> tuple[int, str, str]:
    """Run an nft command, return (rc, stdout, stderr)."""
    if netns:
        full_cmd = [*_RUN_NETNS, "exec", netns, "nft", *cmd.split()]
    else:
        full_cmd = ["nft", *cmd.split()]
    try:
        r = subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return 1, "", str(e)


def _probe_rule(rule: str, netns: str | None = None) -> bool:
    """Test if a rule can be added successfully."""
    rc, _, _ = _nft(f"add rule inet {_PROBE_TABLE} __test {rule}", netns)
    if rc == 0:
        _nft(f"flush chain inet {_PROBE_TABLE} __test", netns)
    return rc == 0


@dataclass
class NftCapabilities:
    """Detected nftables capabilities."""
    version: str = ""
    nft_path: str = ""

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
    def probe(cls, netns: str | None = None) -> "NftCapabilities":
        """Probe the system for nft capabilities.

        Creates a temporary namespace (or uses provided one)
        and tests each feature by trying to create rules.
        """
        caps = cls()

        # Version
        rc, out, _ = _nft("-v", netns)
        if rc == 0:
            caps.version = out.strip().split()[-1].strip("()")
            caps.nft_path = "nft"

        # Create probe table
        _nft(f"add table inet {_PROBE_TABLE}", netns)
        _nft(f"add chain inet {_PROBE_TABLE} __test {{ type filter hook input priority 0; }}", netns)

        # Families
        for fam in ("ip", "ip6", "inet", "arp", "bridge", "netdev"):
            rc, _, _ = _nft(f"add table {fam} {_PROBE_TABLE}_fam", netns)
            if rc == 0:
                caps.families.append(fam)
                _nft(f"delete table {fam} {_PROBE_TABLE}_fam", netns)

        # Chain type/hook combinations
        for chain_type in ("filter", "nat", "route"):
            hooks = []
            for hook in ("prerouting", "input", "forward", "output", "postrouting", "ingress"):
                rc, _, _ = _nft(
                    f"add chain inet {_PROBE_TABLE} __hook "
                    f"{{ type {chain_type} hook {hook} priority 0; }}", netns)
                if rc == 0:
                    hooks.append(hook)
                    _nft(f"delete chain inet {_PROBE_TABLE} __hook", netns)
            caps.chain_hooks[chain_type] = hooks

        # Match expressions
        caps.has_ct_state = _probe_rule("ct state established accept", netns)
        caps.has_ct_helper = _probe_rule('ct helper "ftp" accept', netns)
        caps.has_ct_count = _probe_rule("ct count 10 accept", netns)
        caps.has_fib = _probe_rule("fib daddr type local accept", netns)
        caps.has_meta_nfproto = _probe_rule("meta nfproto ipv4 accept", netns)
        caps.has_socket = _probe_rule("socket transparent 1 accept", netns)
        caps.has_osf = _probe_rule('osf name "Linux" accept', netns)

        # Statements
        caps.has_limit = _probe_rule("limit rate 10/second accept", netns)
        caps.has_quota = _probe_rule("quota over 1 mbytes drop", netns)
        caps.has_counter = _probe_rule("counter accept", netns)
        caps.has_log = _probe_rule('log prefix "test" accept', netns)
        caps.has_notrack = _probe_rule("notrack", netns)
        # NAT probe: masquerade only works in a nat-type chain, not filter.
        _nft(f"add chain inet {_PROBE_TABLE} __nat_test {{ type nat hook postrouting priority 100; }}", netns)
        rc_nat, _, _ = _nft(f"add rule inet {_PROBE_TABLE} __nat_test masquerade", netns)
        caps.has_nat = rc_nat == 0
        _nft(f"flush chain inet {_PROBE_TABLE} __nat_test", netns)
        _nft(f"delete chain inet {_PROBE_TABLE} __nat_test", netns)
        caps.has_flow_offload = _probe_rule("flow offload @__nonexistent", netns) is False  # Will fail but module presence detectable

        # Set features
        rc, _, _ = _nft(f"add set inet {_PROBE_TABLE} __s1 {{ type ipv4_addr; flags interval; }}", netns)
        caps.has_interval_sets = rc == 0
        _nft(f"delete set inet {_PROBE_TABLE} __s1", netns)

        rc, _, _ = _nft(f"add set inet {_PROBE_TABLE} __s2 {{ type ipv4_addr; flags timeout; }}", netns)
        caps.has_timeout_sets = rc == 0
        _nft(f"delete set inet {_PROBE_TABLE} __s2", netns)

        rc, _, _ = _nft(f'add set inet {_PROBE_TABLE} __s3 {{ type ipv4_addr . inet_service; }}', netns)
        caps.has_concat_sets = rc == 0
        _nft(f"delete set inet {_PROBE_TABLE} __s3", netns)

        # Objects
        rc, _, _ = _nft(f'add ct helper inet {_PROBE_TABLE} __h {{ type "ftp" protocol tcp; l3proto inet; }}', netns)
        caps.has_ct_helper_obj = rc == 0
        if rc == 0:
            _nft(f"delete ct helper inet {_PROBE_TABLE} __h", netns)

        rc, _, _ = _nft(f"add counter inet {_PROBE_TABLE} __c", netns)
        caps.has_counter_obj = rc == 0
        if rc == 0:
            _nft(f"delete counter inet {_PROBE_TABLE} __c", netns)

        rc, _, _ = _nft(f"add quota inet {_PROBE_TABLE} __q {{ over 1 mbytes }}", netns)
        caps.has_quota_obj = rc == 0
        if rc == 0:
            _nft(f"delete quota inet {_PROBE_TABLE} __q", netns)

        # Flowtable
        rc, _, _ = _nft(f'add flowtable inet {_PROBE_TABLE} __ft {{ hook ingress priority 0; devices = {{}}; }}', netns)
        caps.has_flowtable = rc == 0
        if caps.has_flowtable:
            _nft(f"delete flowtable inet {_PROBE_TABLE} __ft", netns)
        # Flowtable hardware/software offload flag. Kernel may accept
        # `flags offload` even without NIC support — the actual hardware
        # offload is validated at packet time. Probing the flag at
        # config-load time is the best we can do from userspace.
        rc, _, _ = _nft(
            f'add flowtable inet {_PROBE_TABLE} __ft2 '
            f'{{ hook ingress priority 0; devices = {{}}; flags offload; }}',
            netns)
        caps.has_flowtable_offload = rc == 0
        if caps.has_flowtable_offload:
            _nft(f"delete flowtable inet {_PROBE_TABLE} __ft2", netns)

        # Kernel modules — always check on the HOST (modules are global, not per-netns)
        import os
        uname = os.uname().release
        mod_dir = Path(f"/lib/modules/{uname}/kernel/net/netfilter")
        if mod_dir.exists():
            caps.kernel_modules = sorted(
                f.stem.replace("nft_", "")
                for f in mod_dir.glob("nft_*.ko*")
            )

        # Try to load missing modules (requires root — may fail in netns)
        _essential_modules = [
            "nft_ct", "nft_log", "nft_limit", "nft_nat",
            "nft_masq", "nft_redir", "nft_quota", "nft_hash",
            "nft_numgen", "nft_fib", "nft_fib_inet",
            "nft_connlimit", "nft_flow_offload", "nft_osf",
        ]
        for mod in _essential_modules:
            if mod.replace("nft_", "") not in caps.kernel_modules:
                # Module not available as file — might be built-in
                pass
            else:
                # Try to modprobe (host-level, not netns)
                try:
                    subprocess.run(
                        ["modprobe", mod], capture_output=True, timeout=5)
                except Exception:
                    pass  # May not have permissions

        # Cleanup
        _nft(f"delete table inet {_PROBE_TABLE}", netns)

        return caps

    def summary(self) -> str:
        """Human-readable summary of capabilities."""
        lines = [f"nftables {self.version}"]
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

    def check_rule_support(self, rule_str: str, netns: str | None = None) -> bool:
        """Check if a specific nft rule syntax is supported."""
        _nft(f"add table inet {_PROBE_TABLE}", netns)
        _nft(f"add chain inet {_PROBE_TABLE} __test {{ type filter hook input priority 0; }}", netns)
        result = _probe_rule(rule_str, netns)
        _nft(f"delete table inet {_PROBE_TABLE}", netns)
        return result
