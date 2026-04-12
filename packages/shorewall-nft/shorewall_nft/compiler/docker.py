"""Docker container network integration.

When DOCKER=Yes in shorewall.conf, creates nft rules that allow
Docker container traffic and preserve Docker-created chains.

In nft, Docker integration is simpler than iptables because
nft uses a separate table — Docker's own nft rules don't conflict.
"""

from __future__ import annotations

from shorewall_nft.compiler.ir import (
    FirewallIR,
    Match,
    Rule,
    Verdict,
)


def setup_docker(ir: FirewallIR, settings: dict[str, str]) -> None:
    """Set up Docker integration if configured.

    DOCKER=Yes enables Docker network support.
    DOCKER_BRIDGE specifies the bridge interface (default: docker0).
    """
    docker = settings.get("DOCKER", "No")
    if docker.lower() not in ("yes", "1"):
        return

    bridge = settings.get("DOCKER_BRIDGE", "docker0")

    # Allow traffic from/to docker bridge
    forward = ir.chains.get("forward")
    if forward:
        # Allow established/related from docker bridge
        forward.rules.append(Rule(
            matches=[
                Match(field="iifname", value=bridge),
                Match(field="ct state", value="established,related"),
            ],
            verdict=Verdict.ACCEPT,
            comment="Docker: allow established",
        ))
        # Allow inter-container traffic
        forward.rules.append(Rule(
            matches=[
                Match(field="iifname", value=bridge),
                Match(field="oifname", value=bridge),
            ],
            verdict=Verdict.ACCEPT,
            comment="Docker: inter-container",
        ))
        # Allow outbound from containers
        forward.rules.append(Rule(
            matches=[
                Match(field="iifname", value=bridge),
                Match(field="oifname", value="!=", negate=False),
            ],
            verdict=Verdict.ACCEPT,
            comment="Docker: outbound",
        ))

    # NAT masquerade for docker bridge
    postrouting = ir.chains.get("postrouting")
    if postrouting:
        postrouting.rules.append(Rule(
            matches=[
                Match(field="iifname", value=bridge),
                Match(field="oifname", value=bridge, negate=True),
            ],
            verdict=Verdict.ACCEPT,
            verdict_args="masquerade:",
            comment="Docker: masquerade",
        ))
