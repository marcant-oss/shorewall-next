"""Unit tests for shorewall_nft_stagelab.config."""

import textwrap

import pytest
from pydantic import ValidationError

from shorewall_nft_stagelab.config import Endpoint, Host, StagelabConfig, load  # noqa: F401

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MINIMAL_YAML = textwrap.dedent("""\
    hosts:
      - name: thx1
        address: root@192.168.4.73

    dut:
      kind: external

    endpoints:
      - name: client-lan-a
        host: thx1
        mode: native
        nic: enp1s0f0
        vlan: 10
        ipv4: 10.0.10.100/24
        ipv4_gw: 10.0.10.1
      - name: server-wan-b
        host: thx1
        mode: native
        nic: enp1s0f1
        vlan: 20
        ipv4: 185.1.2.100/30
        ipv4_gw: 185.1.2.99
      - name: probe-any
        host: thx1
        mode: probe
        bridge: br-probes
        nic: enp1s0f2
        vlan: 50
        ipv6: 2a00:f88:10::200/64

    scenarios:
      - id: rule_scan
        kind: rule_scan
        source: probe-any
        target_subnet: 2a00:f88::/32
        random_count: 10

    report:
      output_dir: docs/testing/stagelab-reports
""")


def _write_yaml(tmp_path, content: str, filename: str = "cfg.yaml"):
    p = tmp_path / filename
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_happy_path_roundtrip(tmp_path):
    """Minimal valid YAML parses correctly and key fields are accessible."""
    p = _write_yaml(tmp_path, _MINIMAL_YAML)
    cfg = load(p)

    assert isinstance(cfg, StagelabConfig)
    assert cfg.hosts[0].name == "thx1"
    assert cfg.hosts[0].work_dir == "/root/shorewall-nft"
    assert cfg.dut.kind == "external"
    assert len(cfg.endpoints) == 3
    ep = next(e for e in cfg.endpoints if e.name == "client-lan-a")
    assert ep.mode == "native"
    assert ep.vlan == 10
    assert ep.ipv4 == "10.0.10.100/24"
    assert cfg.scenarios[0].id == "rule_scan"
    assert cfg.metrics.poll_interval_s == 1
    assert cfg.report.keep_pcaps == "failed_only"


def test_unknown_field_is_rejected(tmp_path):
    """An unrecognised key in an endpoint raises ValidationError (extra=forbid)."""
    yaml_text = _MINIMAL_YAML.replace(
        "  - name: client-lan-a",
        "  - name: client-lan-a\n    unknown_key: 1",
    )
    p = _write_yaml(tmp_path, yaml_text)
    with pytest.raises(ValidationError, match="unknown_key"):
        load(p)


def test_duplicate_endpoint_names_rejected(tmp_path):
    """Two endpoints with the same name raise ValidationError."""
    yaml_text = _MINIMAL_YAML.replace(
        "      - name: server-wan-b",
        "      - name: client-lan-a\n        host: thx1\n        mode: native\n        nic: enp1s0f2\n        vlan: 30\n        ipv4: 10.0.30.2/24\n        ipv4_gw: 10.0.30.1\n      - name: _orig_to_remove",
    )
    # Simpler: just build the YAML directly
    yaml_text = textwrap.dedent("""\
        hosts:
          - name: thx1
            address: root@192.168.4.73

        dut:
          kind: external

        endpoints:
          - name: ep-dup
            host: thx1
            mode: native
            nic: enp1s0f0
            vlan: 10
            ipv4: 10.0.10.100/24
            ipv4_gw: 10.0.10.1
          - name: ep-dup
            host: thx1
            mode: native
            nic: enp1s0f1
            vlan: 20
            ipv4: 10.0.20.100/24
            ipv4_gw: 10.0.20.1

        scenarios:
          - id: rule_scan
            kind: rule_scan
            source: ep-dup
            target_subnet: 10.0.0.0/8
            random_count: 5

        report:
          output_dir: /tmp/out
    """)
    p = _write_yaml(tmp_path, yaml_text)
    with pytest.raises(ValidationError, match="duplicate endpoint name"):
        load(p)


def test_scenario_source_must_exist(tmp_path):
    """A scenario referencing a non-existent endpoint name raises ValidationError."""
    yaml_text = textwrap.dedent("""\
        hosts:
          - name: thx1
            address: root@192.168.4.73

        dut:
          kind: external

        endpoints:
          - name: ep-real
            host: thx1
            mode: native
            nic: enp1s0f0
            vlan: 10
            ipv4: 10.0.10.100/24
            ipv4_gw: 10.0.10.1

        scenarios:
          - id: rule_scan
            kind: rule_scan
            source: no-such-endpoint
            target_subnet: 10.0.0.0/8
            random_count: 5

        report:
          output_dir: /tmp/out
    """)
    p = _write_yaml(tmp_path, yaml_text)
    with pytest.raises(ValidationError, match="source.*not found in endpoints"):
        load(p)


def test_probe_endpoint_requires_bridge(tmp_path):
    """A probe-mode endpoint without 'bridge' set raises ValidationError."""
    yaml_text = textwrap.dedent("""\
        hosts:
          - name: thx1
            address: root@192.168.4.73

        dut:
          kind: external

        endpoints:
          - name: probe-no-bridge
            host: thx1
            mode: probe
            nic: enp1s0f0
            vlan: 10
            ipv6: 2a00:f88:10::200/64

        scenarios:
          - id: rule_scan
            kind: rule_scan
            source: probe-no-bridge
            target_subnet: 2a00:f88::/32
            random_count: 5

        report:
          output_dir: /tmp/out
    """)
    p = _write_yaml(tmp_path, yaml_text)
    with pytest.raises(ValidationError, match="must set 'bridge'"):
        load(p)


def test_native_and_probe_on_same_nic_rejected(tmp_path):
    """A native endpoint and a probe endpoint on the same (host, nic) raises ValidationError."""
    yaml_text = textwrap.dedent("""\
        hosts:
          - name: thx1
            address: root@192.168.4.73

        dut:
          kind: external

        endpoints:
          - name: native-ep
            host: thx1
            mode: native
            nic: enp1s0f0
            vlan: 10
            ipv4: 10.0.10.100/24
            ipv4_gw: 10.0.10.1
          - name: probe-ep
            host: thx1
            mode: probe
            bridge: br-probes
            nic: enp1s0f0
            vlan: 20
            ipv6: 2a00:f88:20::200/64

        scenarios:
          - id: rule_scan
            kind: rule_scan
            source: probe-ep
            target_subnet: 2a00:f88::/32
            random_count: 5

        report:
          output_dir: /tmp/out
    """)
    p = _write_yaml(tmp_path, yaml_text)
    with pytest.raises(ValidationError, match="probe and native"):
        load(p)
