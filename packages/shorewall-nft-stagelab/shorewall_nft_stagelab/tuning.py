"""RSS, IRQ affinity, sysctl tuning, and hugepages stub for isolated traffic-gen cores."""

import re
import subprocess
from pathlib import Path

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_IFACE_RE = re.compile(r"^[A-Za-z0-9_-]{1,15}$")


def _check_iface(iface: str) -> None:
    if not _IFACE_RE.match(iface):
        raise ValueError(f"Invalid interface name: {iface!r}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

DEFAULT_HIGH_PPS_SYSCTLS: dict[str, str] = {
    "net.netfilter.nf_conntrack_max": "4194304",
    "net.core.rmem_max": "134217728",
    "net.core.wmem_max": "134217728",
}


def apply_rss(iface: str, queues: int) -> None:
    """Set the number of RX+TX combined queues on `iface` via ethtool.

    Effective command:  ethtool -L <iface> combined <queues>
    """
    _check_iface(iface)
    if queues < 1:
        raise ValueError(f"queues must be >= 1, got {queues}")
    cmd = ["ethtool", "-L", iface, "combined", str(queues)]
    result = subprocess.run(cmd, check=True, text=True, capture_output=True)
    if result.returncode != 0:  # pragma: no cover — check=True raises first
        raise RuntimeError(f"ethtool failed: {result.stderr}")


def set_irq_affinity(iface: str, cores: list[int]) -> None:
    """Pin the per-queue IRQs of `iface` to the given CPU cores.

    1. Read /proc/interrupts to find IRQ lines whose description contains
       the iface name (e.g. "mlx5_core.*<iface>" or "<iface>-TxRx-N").
    2. For each such IRQ number N, write a CPU mask (from cores list) to
       /proc/irq/N/smp_affinity_list (comma-separated decimal list is
       accepted).
    Raise RuntimeError if no IRQs are found for the iface.
    """
    _check_iface(iface)
    if any(c < 0 for c in cores):
        raise ValueError(f"All core indices must be >= 0, got {cores}")

    with open("/proc/interrupts") as fh:
        lines = fh.readlines()

    irq_nums: list[str] = []
    for line in lines:
        # Format: "  42:  <counts...>  <description>"
        # Description is the right-most field(s) after the last count column.
        stripped = line.strip()
        if not stripped:
            continue
        # First token ends with ':', giving the IRQ number.
        parts = stripped.split(":", 1)
        if len(parts) != 2:
            continue
        irq_candidate = parts[0].strip()
        description = parts[1]
        if iface in description:
            irq_nums.append(irq_candidate)

    if not irq_nums:
        raise RuntimeError(
            f"No IRQ lines found for interface {iface!r} in /proc/interrupts"
        )

    affinity = ",".join(str(c) for c in cores)
    for irq in irq_nums:
        affinity_path = Path(f"/proc/irq/{irq}/smp_affinity_list")
        affinity_path.write_text(affinity)


def apply_sysctls(settings: dict[str, str]) -> None:
    """Apply a dict of sysctl key=value via `sysctl -w key=value`.

    Example:
        apply_sysctls({
            "net.netfilter.nf_conntrack_max": "4194304",
            "net.core.rmem_max": "134217728",
            "net.core.wmem_max": "134217728",
        })
    """
    for key, value in settings.items():
        cmd = ["sysctl", "-w", f"{key}={value}"]
        result = subprocess.run(cmd, check=True, text=True, capture_output=True)
        if result.returncode != 0:  # pragma: no cover — check=True raises first
            raise RuntimeError(f"sysctl failed for {key}: {result.stderr}")
