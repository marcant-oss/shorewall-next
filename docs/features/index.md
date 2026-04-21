# Features

**Audience**: operators
**Scope**: Per-feature configuration references for Shorewall — NAT, VPN, QoS, logging, and more.

---

## Overview

Each file here documents one Shorewall feature in depth.
For foundational concepts, see `docs/concepts/`. For setup walkthroughs, see `docs/reference/`.

## Files in this area

| File | Description |
|------|-------------|
| [Accounting.md](Accounting.md) | Packet/byte counters via accounting rules |
| [Anti-Spoofing.md](Anti-Spoofing.md) | Source-address spoofing countermeasures |
| [Audit.md](Audit.md) | Linux Audit records for accepted/dropped packets |
| [ConnectionRate.md](ConnectionRate.md) | Per-zone connection-rate limiting |
| [dhcp.md](dhcp.md) | Coexistence with DHCP clients and servers |
| [Docker.md](Docker.md) | Running alongside Docker without rule conflicts |
| [Dynamic.md](Dynamic.md) | ipset-backed dynamic zones |
| [ECN.md](ECN.md) | Selective ECN clearing for broken peers |
| [fallback.md](fallback.md) | Rolling back to a previous Shorewall version |
| [FTP.md](FTP.md) | Active and passive FTP with ct helpers |
| [GenericTunnels.md](GenericTunnels.md) | Arbitrary tunnel types |
| [Helpers.md](Helpers.md) | Connection tracking helpers (FTP, SIP, H.323) |
| [IPIP.md](IPIP.md) | IP-in-IP and GRE tunnels |
| [IPSEC.md](IPSEC.md) | IPsec tunnels and transport-mode connections |
| [ipsets.md](ipsets.md) | ipset-backed address sets |
| [IPv6Support.md](IPv6Support.md) | Dual-stack and IPv6-only configuration |
| [KVM.md](KVM.md) | KVM hypervisor host configuration |
| [Laptop.md](Laptop.md) | Roaming firewall for multiple transient interfaces |
| [LXC.md](LXC.md) | LXC container host configuration |
| [MAC_Validation.md](MAC_Validation.md) | Restricting traffic by MAC address |
| [MultiISP.md](MultiISP.md) | Policy routing across multiple ISP connections |
| [NAT.md](NAT.md) | Static NAT, DNAT, SNAT, masquerade |
| [netmap.md](netmap.md) | Network address range rewriting |
| [nfsets.md](nfsets.md) | Named dynamic nft sets (dnstap / resolver / ip-list backends) |
| [OPENVPN.md](OPENVPN.md) | OpenVPN tunnel and server rules |
| [PacketHandling.md](PacketHandling.md) | Packet traversal through a Shorewall firewall |
| [PacketMarking.md](PacketMarking.md) | MARK/CONNMARK for QoS and policy routing |
| [ping.md](ping.md) | ICMP ping rules across zones |
| [PortKnocking.md](PortKnocking.md) | Legacy port-knocking (superseded by Events) |
| [ports.md](ports.md) | Common protocol port numbers |
| [ProxyARP.md](ProxyARP.md) | Proxy ARP for public-address hosts behind a router |
| [QOSExample.md](QOSExample.md) | Complete QoS/traffic-shaping example |
| [SharedConfig.md](SharedConfig.md) | Sharing config between shorewall and shorewall6 |
| [Shorewall_and_Routing.md](Shorewall_and_Routing.md) | Relationship between firewalling and routing |
| [Shorewall-Lite.md](Shorewall-Lite.md) | Deploying compiled rulesets to appliances |
| [shorewall_logging.md](shorewall_logging.md) | Packet logging: levels, prefixes, targets |
| [Shorewall_Squid_Usage.md](Shorewall_Squid_Usage.md) | Squid transparent and manual proxy |
| [SimpleBridge.md](SimpleBridge.md) | Layer-2 bridge firewall |
| [simple_traffic_shaping.md](simple_traffic_shaping.md) | Basic bandwidth control |
| [SplitDNS.md](SplitDNS.md) | Different DNS responses for internal/external |
| [traffic_shaping.md](traffic_shaping.md) | Advanced QoS with tc HTB/HFSC |
| [Universal.md](Universal.md) | Universal single-system configuration sample |
| [VPNBasics.md](VPNBasics.md) | Gateway-to-gateway vs host-to-host VPN concepts |
| [VPN.md](VPN.md) | IPsec and PPTP for hosts behind the firewall |
| [whitelisting_under_shorewall.md](whitelisting_under_shorewall.md) | Privileged access via dedicated zone |

## See also

- [docs/concepts/](../concepts/index.md) — foundational concepts
- [docs/reference/](../reference/index.md) — setup guides
- [docs/index.md](../index.md) — documentation root
