"""Generate systemd service templates for shorewall-nft.

Creates:
- shorewall-nft.service (init namespace)
- shorewall-nft@.service (per-namespace template)
"""

from __future__ import annotations


def generate_service() -> str:
    """Generate shorewall-nft.service for the init namespace."""
    return """\
[Unit]
Description=shorewall-nft firewall
After=network-pre.target
Before=network.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/shorewall-nft apply /etc/shorewall-nft/
ExecReload=/usr/bin/shorewall-nft apply /etc/shorewall-nft/
ExecStop=/usr/sbin/nft delete table inet shorewall

[Install]
WantedBy=multi-user.target
"""


def generate_netns_service() -> str:
    """Generate shorewall-nft@.service template for per-namespace deployment."""
    return """\
[Unit]
Description=shorewall-nft firewall for netns %i
After=netns@%i.service netns-network@%i.service
Requires=netns@%i.service
BindsTo=netns@%i.service
JoinsNamespaceOf=netns@%i.service
PartOf=netns@%i.service

[Service]
Type=oneshot
RemainAfterExit=yes
PrivateNetwork=true
ExecStart=/usr/bin/shorewall-nft apply /etc/shorewall-nft/%i/
ExecReload=/usr/bin/shorewall-nft apply /etc/shorewall-nft/%i/
ExecStop=/usr/sbin/nft delete table inet shorewall

[Install]
WantedBy=netns@%i.service
"""
