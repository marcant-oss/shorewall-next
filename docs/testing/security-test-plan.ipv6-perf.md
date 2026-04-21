# Performance addendum — IPv6 throughput

Merged by M1 into security-test-plan.md.

## In scope

- TCP throughput parity with IPv4 over a native IPv6 endpoint pair.
- UDP throughput parity over a native IPv6 endpoint pair.
- Conntrack table health under sustained throughput and connection storms.
- Through-FW conntrack probe: exercises real FW forwarding path without FW config changes.

## Test catalogue

### perf-ipv6-tcp-throughput — IPv6 TCP throughput meets SLO

- **Scenario**: `throughput` with `proto: tcp` and IPv6-native endpoints (`fd00:10:0:13::100/64` and `fd00:10:0:13::200/64`).
- **Acceptance**: `min_gbps >= 8.0` AND `max_retrans_ratio <= 0.005`.
- **Standard refs**: NIST SP 800-53 SC-7 (boundary protection).
- **Evidence**: `audit.json scenarios[].test_id == perf-ipv6-tcp-throughput`.
- **Rationale**: SC-7 boundary protection applies to IPv6 as much as IPv4; throughput parity must be demonstrated to confirm the firewall does not introduce IPv6-specific performance degradation.

### perf-ipv6-udp-throughput — IPv6 UDP throughput meets SLO

- **Scenario**: `throughput` with `proto: udp` and IPv6-native endpoints.
- **Acceptance**: `min_gbps >= 5.0`.
- **Standard refs**: NIST SP 800-53 SC-7 (boundary protection).
- **Evidence**: `audit.json scenarios[].test_id == perf-ipv6-udp-throughput`.
- **Rationale**: UDP-based protocols (DNS, NTP, syslog, media) traverse the firewall over IPv6 in dual-stack deployments.  Throughput parity reduces the risk of a performance cliff when clients migrate to IPv6.

### perf-through-fw-conntrack-probe — Through-FW conntrack probe via existing ACCEPT rule

- **Scenario**: `conn_storm_direct` targeting the reference HA firewall's SSHd
  (`203.0.113.75:22`) from a native-mode endpoint in the `net` zone backbone
  (`203.0.113.64/27`, tester01 eth2).
- **Rule used**: `SSH(ACCEPT) net:203.0.113.64/27 $FW` — line 47 of the reference
  HA firewall's `/etc/shorewall/rules`.  No FW config change is required.
- **Traffic path**: tester01 eth2 (`203.0.113.74/27`) → FW `bond1`
  (`203.0.113.75`) tcp/22 → conntrack ESTABLISHED in the `net → $FW` INPUT chain.
- **Acceptance**: `conntrack_peak_observed > 0` (any FW-side conntrack activity
  confirms the flow traverses the FW's netfilter stack).
- **Standard refs**: NIST SP 800-53 SC-7 (boundary protection — stateful inspection
  must record connection state for all permitted flows).
- **Evidence**: `audit.json scenarios[].test_id == perf-through-fw-conntrack-probe`;
  `scenarios[].raw.conntrack_peak_observed > 0`.
- **Operator caveat**: the sim-uplink OSPF netns (router ID `203.0.113.77`) also
  claims eth2; it must be stopped before this scenario runs.  See the
  `net-backbone-native` endpoint comment in `tools/stagelab-fw-test-live.yaml`.
  SSH brute-force mitigation (`MaxStartups`/fail2ban) may limit the observed peak
  to ≤10% of `target_conns` — that is still a valid non-zero result.

## Running these tests

Use the example config `tools/stagelab-example-ipv6-throughput.yaml`:

```bash
.venv/bin/stagelab validate tools/stagelab-example-ipv6-throughput.yaml
.venv/bin/stagelab run tools/stagelab-example-ipv6-throughput.yaml
```

The example config requires physical interfaces on the two tester hosts.  Adjust
`nic`, `vlan`, and the ULA prefix (`fd00:10:0:13::/64`) to match the deployment.

## Out of scope

- **IPv6-only transition / NAT64** — the reference firewall is dual-stack; the NAT64 appliance is a separate component.
- **IPv6 flow-label QoS** — not a firewall-level concern; deferred to the network-layer QoS test plan.
- **MLD (Multicast Listener Discovery)** — handled by CIS/OWASP protocol-stack test items; out of scope for throughput parity.
