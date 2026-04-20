"""Unit tests for DnsDosScenario (config), DnsDosRunner (scenarios),
and trafgen_trex_dns_builder."""

from __future__ import annotations

import struct
import textwrap

import pytest
import yaml

from shorewall_nft_stagelab.config import StagelabConfig
from shorewall_nft_stagelab.scenarios import (
    AgentCommand,
    DnsDosRunner,
    build_runner,
)
from shorewall_nft_stagelab.trafgen_trex_dns_builder import build_dns_question

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BASE_YAML = textwrap.dedent("""\
    hosts:
      - name: tester
        address: root@192.168.4.73

    dut:
      kind: external

    endpoints:
      - name: dpdk-src
        host: tester
        mode: dpdk
        pci_addr: "0000:01:00.0"
        dpdk_cores: [2, 3]
        hugepages_gib: 4
        trex_role: client
        ipv4: 10.0.0.1/24
      - name: dpdk-sink
        host: tester
        mode: dpdk
        pci_addr: "0000:01:00.1"
        dpdk_cores: [4, 5]
        hugepages_gib: 4
        trex_role: server
        ipv4: 10.0.0.200/24

    dos_target_allowlist:
      - 10.0.1.0/24

    scenarios:
      - id: dns-dos-1
        kind: dos_dns_query
        source: dpdk-src
        sink: dpdk-sink
        duration_s: 10
        queries_per_s: 50000
        query_name_pattern: fixed
        target_resolver: 10.0.1.53
        fixed_qname: test.example.com

    report:
      output_dir: /tmp/out
""")


def _load(yaml_text: str) -> StagelabConfig:
    return StagelabConfig.model_validate(yaml.safe_load(yaml_text))


# ---------------------------------------------------------------------------
# Test 1 — build_dns_question: wire-format header is well-formed
# ---------------------------------------------------------------------------


def test_build_dns_wire_format_random_qname():
    pkt = build_dns_question("test-abc.example.com")
    # Must be at least 12 (header) + some question bytes
    assert len(pkt) >= 12 + 1  # header + at least \x00 terminator

    # Parse header fields
    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack_from("!HHHHHH", pkt, 0)
    assert txid == 0x1234
    assert flags == 0x0100           # standard query, recursion desired
    assert qdcount == 1
    assert ancount == 0
    assert nscount == 0
    assert arcount == 0

    # QNAME labels: first byte is length of "test-abc" = 8
    assert pkt[12] == 8


# ---------------------------------------------------------------------------
# Test 2 — build_dns_question: QTYPE=ANY (255) at correct offset
# ---------------------------------------------------------------------------


def test_build_dns_wire_amplification_qtype_any():
    pkt = build_dns_question("example.com", qtype="ANY")
    # QNAME wire for "example.com": \x07example\x03com\x00 = 1+7+1+3+1 = 13 bytes
    qname_wire_len = 1 + 7 + 1 + 3 + 1  # = 13
    qtype_offset = 12 + qname_wire_len
    (qtype_val,) = struct.unpack_from("!H", pkt, qtype_offset)
    assert qtype_val == 255  # ANY


# ---------------------------------------------------------------------------
# Test 3 — DnsDosRunner.plan() returns 1 AgentCommand with correct spec
# ---------------------------------------------------------------------------


def test_dns_dos_plan_one_command():
    cfg = _load(_BASE_YAML)
    sc = cfg.scenarios[0]
    assert sc.kind == "dos_dns_query"
    runner = build_runner(sc)
    assert isinstance(runner, DnsDosRunner)

    commands = runner.plan(cfg)
    assert len(commands) == 1
    cmd = commands[0]
    assert isinstance(cmd, AgentCommand)
    assert cmd.kind == "run_trex_stateless"
    assert cmd.endpoint_name == "dpdk-src"

    spec = cmd.spec
    assert spec["ports"] == (0,)          # dpdk-src is trex_port_id=0
    assert spec["duration_s"] == 10
    assert spec["multiplier"] == "50000pps"
    assert "profile_text" in spec
    assert isinstance(spec["profile_text"], str)
    assert len(spec["profile_text"]) > 0
    assert spec["scenario_id"] == "dns-dos-1"


# ---------------------------------------------------------------------------
# Test 4 — resolver outside allowlist raises ValidationError
# ---------------------------------------------------------------------------


def test_dns_dos_allowlist_rejects_outside_resolver():
    yaml_text = textwrap.dedent("""\
        hosts:
          - name: tester
            address: root@192.168.4.73

        dut:
          kind: external

        endpoints:
          - name: dpdk-src
            host: tester
            mode: dpdk
            pci_addr: "0000:01:00.0"
            dpdk_cores: [2, 3]
            hugepages_gib: 4
            trex_role: client
          - name: dpdk-sink
            host: tester
            mode: dpdk
            pci_addr: "0000:01:00.1"
            dpdk_cores: [4, 5]
            hugepages_gib: 4
            trex_role: server

        dos_target_allowlist:
          - 10.0.0.0/24

        scenarios:
          - id: dns-dos-outside
            kind: dos_dns_query
            source: dpdk-src
            sink: dpdk-sink
            queries_per_s: 10000
            target_resolver: 192.168.99.53

        report:
          output_dir: /tmp/out
    """)
    from pydantic import ValidationError

    with pytest.raises(ValidationError) as exc_info:
        _load(yaml_text)
    assert "dos_target_allowlist" in str(exc_info.value)
