## shorewall-nft-stagelab

Distributed bridge-lab for shorewall-nft performance and readiness testing.
Drives synthetic traffic from a high-throughput test host (25 G+ NIC) through
a real firewall appliance via VLAN trunk, in two modes: `probe` (TAP in
VLAN-bridge, scapy-backed, ~1 Gbps) and `native` (physical NIC moved into
netns, iperf3/tcpkali/nmap, 10–25 Gbps / 1 M concurrent connections).

This package is complementary to `shorewall-nft-simlab`, not a replacement:
simlab validates correctness of the compiled ruleset via oracle + scapy probes
inside a local netns; stagelab validates performance and readiness against real
firewall hardware under production-grade load.

See the design plan at `~/.claude/plans/bei-den-performance-tests-foamy-fern.md`.
