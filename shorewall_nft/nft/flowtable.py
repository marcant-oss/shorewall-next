"""Flowtable generation for hardware/software offloading.

Generates nft flowtable declarations and flow offload rules
in the forward chain.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Flowtable:
    """An nft flowtable for connection offloading."""
    name: str = "ft"
    hook: str = "ingress"
    priority: int = 0
    devices: list[str] = field(default_factory=list)
    offload: bool = False  # hardware offload


def emit_flowtable(ft: Flowtable) -> str:
    """Generate nft flowtable declaration."""
    devices = ", ".join(f'"{d}"' for d in ft.devices)
    hw = "\n\t\tflags offload;" if ft.offload else ""
    return f"""\tflowtable {ft.name} {{
\t\thook {ft.hook} priority {ft.priority};{hw}
\t\tdevices = {{ {devices} }};
\t}}"""


def emit_flow_offload_rule(ft_name: str = "ft") -> str:
    """Generate a flow offload rule for the forward chain."""
    return f"ct state established flow add @{ft_name}"
