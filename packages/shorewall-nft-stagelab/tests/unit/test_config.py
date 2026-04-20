"""Unit tests for shorewall_nft_stagelab.config."""

import textwrap

import pytest
from pydantic import ValidationError

from shorewall_nft_stagelab.config import (  # noqa: F401
    Endpoint,
    Host,
    PrometheusSourceSpec,
    SNMPSourceSpec,
    StagelabConfig,
    load,
    total_hugepages_per_host,
)

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


def test_metrics_sources_parse(tmp_path):
    """metrics.sources with Prometheus + SNMP entries parses to correct types."""
    yaml_text = textwrap.dedent("""\
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

        scenarios:
          - id: rule_scan
            kind: rule_scan
            source: client-lan-a
            target_subnet: 10.0.0.0/8
            random_count: 5

        metrics:
          poll_interval_s: 2
          sources:
            - kind: prometheus
              name: fw-shorewalld
              url: http://192.168.4.73:9100/metrics
              timeout_s: 4.0
              metric_prefix_allow:
                - shorewalld_
            - kind: snmp
              name: sw-core
              host: 192.168.1.1
              community: public
              oids:
                - "1.3.6.1.2.1.1.1.0"
              port: 161

        report:
          output_dir: /tmp/out
    """)
    p = _write_yaml(tmp_path, yaml_text)
    cfg = load(p)

    assert len(cfg.metrics.sources) == 2
    prom_src = cfg.metrics.sources[0]
    snmp_src = cfg.metrics.sources[1]
    assert isinstance(prom_src, PrometheusSourceSpec)
    assert prom_src.name == "fw-shorewalld"
    assert prom_src.url == "http://192.168.4.73:9100/metrics"
    assert prom_src.metric_prefix_allow == ["shorewalld_"]
    assert isinstance(snmp_src, SNMPSourceSpec)
    assert snmp_src.host == "192.168.1.1"
    assert snmp_src.community == "public"
    assert snmp_src.oids == ["1.3.6.1.2.1.1.1.0"]


# ---------------------------------------------------------------------------
# DPDK endpoint tests
# ---------------------------------------------------------------------------

_DPDK_YAML_BASE = textwrap.dedent("""\
    hosts:
      - name: thx1
        address: root@192.168.4.73

    dut:
      kind: external

    endpoints:
      - name: dpdk-client
        host: thx1
        mode: dpdk
        pci_addr: "0000:01:00.0"
        dpdk_cores: [2, 3]
        hugepages_gib: 4
        trex_role: client
      - name: dpdk-server
        host: thx1
        mode: dpdk
        pci_addr: "0000:01:00.1"
        dpdk_cores: [4, 5]
        hugepages_gib: 4
        trex_role: server

    scenarios:
      - id: throughput_dpdk
        kind: throughput
        source: dpdk-client
        sink: dpdk-server
        proto: udp
        duration_s: 10
        parallel: 1
        expect_min_gbps: 1.0

    report:
      output_dir: /tmp/out
""")


def test_dpdk_endpoint_valid(tmp_path):
    """A well-formed dpdk endpoint parses correctly."""
    p = _write_yaml(tmp_path, _DPDK_YAML_BASE)
    cfg = load(p)
    assert cfg.endpoints[0].mode == "dpdk"
    assert cfg.endpoints[0].pci_addr == "0000:01:00.0"
    assert cfg.endpoints[0].dpdk_cores == [2, 3]
    assert cfg.endpoints[0].hugepages_gib == 4
    assert cfg.endpoints[0].trex_role == "client"
    totals = total_hugepages_per_host(cfg)
    assert totals == {"thx1": 8}


def test_dpdk_endpoint_missing_pci_rejected(tmp_path):
    """A dpdk endpoint without pci_addr raises ValidationError mentioning pci."""
    yaml_text = textwrap.dedent("""\
        hosts:
          - name: thx1
            address: root@192.168.4.73

        dut:
          kind: external

        endpoints:
          - name: dpdk-nopci
            host: thx1
            mode: dpdk
            dpdk_cores: [2, 3]
            hugepages_gib: 4
            trex_role: client

        scenarios:
          - id: throughput_dpdk
            kind: throughput
            source: dpdk-nopci
            sink: dpdk-nopci
            proto: udp
            duration_s: 10
            parallel: 1
            expect_min_gbps: 1.0

        report:
          output_dir: /tmp/out
    """)
    p = _write_yaml(tmp_path, yaml_text)
    with pytest.raises(ValidationError, match="pci"):
        load(p)


def test_dpdk_duplicate_pci_on_same_host_rejected(tmp_path):
    """Two dpdk endpoints on the same host with the same pci_addr raise ValidationError."""
    yaml_text = textwrap.dedent("""\
        hosts:
          - name: thx1
            address: root@192.168.4.73

        dut:
          kind: external

        endpoints:
          - name: dpdk-a
            host: thx1
            mode: dpdk
            pci_addr: "0000:01:00.0"
            dpdk_cores: [2]
            hugepages_gib: 2
            trex_role: client
          - name: dpdk-b
            host: thx1
            mode: dpdk
            pci_addr: "0000:01:00.0"
            dpdk_cores: [3]
            hugepages_gib: 2
            trex_role: server

        scenarios:
          - id: throughput_dpdk
            kind: throughput
            source: dpdk-a
            sink: dpdk-b
            proto: udp
            duration_s: 10
            parallel: 1
            expect_min_gbps: 1.0

        report:
          output_dir: /tmp/out
    """)
    p = _write_yaml(tmp_path, yaml_text)
    with pytest.raises(ValidationError, match="duplicate pci_addr"):
        load(p)


def test_dpdk_fields_rejected_on_native_mode(tmp_path):
    """A native endpoint with pci_addr set raises ValidationError."""
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
            pci_addr: "0000:01:00.0"

        scenarios:
          - id: rule_scan
            kind: rule_scan
            source: native-ep
            target_subnet: 10.0.0.0/8
            random_count: 5

        report:
          output_dir: /tmp/out
    """)
    p = _write_yaml(tmp_path, yaml_text)
    with pytest.raises(ValidationError, match="pci_addr"):
        load(p)


# ---------------------------------------------------------------------------
# DPDK scenario validator tests
# ---------------------------------------------------------------------------


def test_throughput_dpdk_requires_dpdk_endpoints(tmp_path):
    """A throughput_dpdk scenario referencing a native-mode endpoint raises ValidationError."""
    yaml_text = textwrap.dedent("""\
        hosts:
          - name: thx1
            address: root@192.168.4.73

        dut:
          kind: external

        endpoints:
          - name: native-src
            host: thx1
            mode: native
            nic: enp1s0f0
            vlan: 10
            ipv4: 10.0.10.100/24
            ipv4_gw: 10.0.10.1
          - name: native-dst
            host: thx1
            mode: native
            nic: enp1s0f1
            vlan: 20
            ipv4: 10.0.20.100/24
            ipv4_gw: 10.0.20.1

        scenarios:
          - id: tput-bad
            kind: throughput_dpdk
            source: native-src
            sink: native-dst
            duration_s: 10
            multiplier: "10gbps"

        report:
          output_dir: /tmp/out
    """)
    p = _write_yaml(tmp_path, yaml_text)
    with pytest.raises(ValidationError, match="dpdk endpoint"):
        load(p)


# ---------------------------------------------------------------------------
# trex_port_id assignment tests
# ---------------------------------------------------------------------------


def test_trex_port_ids_assigned_consecutively(tmp_path):
    """3 DPDK endpoints on one host receive consecutive trex_port_ids 0, 1, 2."""
    yaml_text = textwrap.dedent("""\
        hosts:
          - name: thx1
            address: root@192.168.4.73

        dut:
          kind: external

        endpoints:
          - name: dpdk-a
            host: thx1
            mode: dpdk
            pci_addr: "0000:01:00.0"
            dpdk_cores: [2]
            hugepages_gib: 2
            trex_role: client
          - name: dpdk-b
            host: thx1
            mode: dpdk
            pci_addr: "0000:01:00.1"
            dpdk_cores: [3]
            hugepages_gib: 2
            trex_role: server
          - name: dpdk-c
            host: thx1
            mode: dpdk
            pci_addr: "0000:01:00.2"
            dpdk_cores: [4]
            hugepages_gib: 2
            trex_role: client

        scenarios:
          - id: tput-dpdk
            kind: throughput_dpdk
            source: dpdk-a
            sink: dpdk-b
            duration_s: 10
            multiplier: "10gbps"

        report:
          output_dir: /tmp/out
    """)
    p = _write_yaml(tmp_path, yaml_text)
    cfg = load(p)
    ids = [ep.trex_port_id for ep in cfg.endpoints]
    assert ids == [0, 1, 2]


def test_trex_port_ids_per_host_independent(tmp_path):
    """DPDK endpoints on different hosts get independent port-ID sequences."""
    yaml_text = textwrap.dedent("""\
        hosts:
          - name: host-a
            address: root@192.168.4.10
          - name: host-b
            address: root@192.168.4.11

        dut:
          kind: external

        endpoints:
          - name: a-ep0
            host: host-a
            mode: dpdk
            pci_addr: "0000:01:00.0"
            dpdk_cores: [2]
            hugepages_gib: 2
            trex_role: client
          - name: a-ep1
            host: host-a
            mode: dpdk
            pci_addr: "0000:01:00.1"
            dpdk_cores: [3]
            hugepages_gib: 2
            trex_role: server
          - name: b-ep0
            host: host-b
            mode: dpdk
            pci_addr: "0000:02:00.0"
            dpdk_cores: [2]
            hugepages_gib: 2
            trex_role: client

        scenarios:
          - id: tput-dpdk
            kind: throughput_dpdk
            source: a-ep0
            sink: a-ep1
            duration_s: 10
            multiplier: "10gbps"

        report:
          output_dir: /tmp/out
    """)
    p = _write_yaml(tmp_path, yaml_text)
    cfg = load(p)
    ep_map = {ep.name: ep.trex_port_id for ep in cfg.endpoints}
    assert ep_map["a-ep0"] == 0
    assert ep_map["a-ep1"] == 1
    assert ep_map["b-ep0"] == 0


def test_non_dpdk_endpoints_trex_port_id_is_none(tmp_path):
    """native and probe endpoints always have trex_port_id=None."""
    yaml_text = textwrap.dedent("""\
        hosts:
          - name: thx1
            address: root@192.168.4.73

        dut:
          kind: external

        endpoints:
          - name: dpdk-tx
            host: thx1
            mode: dpdk
            pci_addr: "0000:01:00.0"
            dpdk_cores: [2]
            hugepages_gib: 2
            trex_role: client
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
            nic: enp1s0f1
            vlan: 20
            ipv6: 2a00:f88:20::200/64

        scenarios:
          - id: tput-dpdk
            kind: throughput_dpdk
            source: dpdk-tx
            sink: dpdk-tx
            duration_s: 10
            multiplier: "10gbps"

        report:
          output_dir: /tmp/out
    """)
    p = _write_yaml(tmp_path, yaml_text)
    cfg = load(p)
    ep_map = {ep.name: ep for ep in cfg.endpoints}
    assert ep_map["dpdk-tx"].trex_port_id == 0
    assert ep_map["native-ep"].trex_port_id is None
    assert ep_map["probe-ep"].trex_port_id is None


# ---------------------------------------------------------------------------
# TRex multiplier validator tests
# ---------------------------------------------------------------------------

_DPDK_MULTIPLIER_YAML_TMPL = textwrap.dedent("""\
    hosts:
      - name: thx1
        address: root@192.168.4.73

    dut:
      kind: external

    endpoints:
      - name: dpdk-client
        host: thx1
        mode: dpdk
        pci_addr: "0000:01:00.0"
        dpdk_cores: [2, 3]
        hugepages_gib: 4
        trex_role: client
      - name: dpdk-server
        host: thx1
        mode: dpdk
        pci_addr: "0000:01:00.1"
        dpdk_cores: [4, 5]
        hugepages_gib: 4
        trex_role: server

    scenarios:
      - id: tput
        kind: throughput_dpdk
        source: dpdk-client
        sink: dpdk-server
        duration_s: 10
        multiplier: "{multiplier}"

    report:
      output_dir: /tmp/out
""")


def test_multiplier_accepts_common_forms(tmp_path):
    """Valid multiplier strings parse without error."""
    for val in ("10gbps", "50%", "1.5mpps", "1000bps", "200KPPS"):
        yaml_text = _DPDK_MULTIPLIER_YAML_TMPL.format(multiplier=val)
        p = _write_yaml(tmp_path, yaml_text)
        cfg = load(p)
        assert cfg.scenarios[0].multiplier == val


def test_multiplier_rejects_typos(tmp_path):
    """Typo multiplier strings raise ValidationError mentioning 'multiplier'."""
    for val in ("gbbps", "10 gbps", "10gb", "gbps"):
        yaml_text = _DPDK_MULTIPLIER_YAML_TMPL.format(multiplier=val)
        p = _write_yaml(tmp_path, yaml_text)
        with pytest.raises(ValidationError, match="multiplier"):
            load(p)


def test_multiplier_rejects_unit_mismatch(tmp_path):
    """Bare number or unknown unit raises ValidationError mentioning 'multiplier'."""
    for val in ("mb", "0.5"):
        yaml_text = _DPDK_MULTIPLIER_YAML_TMPL.format(multiplier=val)
        p = _write_yaml(tmp_path, yaml_text)
        with pytest.raises(ValidationError, match="multiplier"):
            load(p)


def test_conn_storm_astf_valid(tmp_path):
    """A conn_storm_astf scenario with two dpdk endpoints parses correctly."""
    yaml_text = textwrap.dedent("""\
        hosts:
          - name: thx1
            address: root@192.168.4.73

        dut:
          kind: external

        endpoints:
          - name: dpdk-client
            host: thx1
            mode: dpdk
            pci_addr: "0000:01:00.0"
            dpdk_cores: [2, 3]
            hugepages_gib: 4
            trex_role: client
          - name: dpdk-server
            host: thx1
            mode: dpdk
            pci_addr: "0000:01:00.1"
            dpdk_cores: [4, 5]
            hugepages_gib: 4
            trex_role: server

        scenarios:
          - id: astf-valid
            kind: conn_storm_astf
            source: dpdk-client
            sink: dpdk-server
            profile_py: /opt/trex/profiles/http.py
            duration_s: 30
            multiplier: 1.5
            expect_min_concurrent: 50000

        report:
          output_dir: /tmp/out
    """)
    p = _write_yaml(tmp_path, yaml_text)
    cfg = load(p)
    sc = cfg.scenarios[0]
    assert sc.kind == "conn_storm_astf"
    assert sc.source == "dpdk-client"
    assert sc.sink == "dpdk-server"
    assert sc.multiplier == 1.5
    assert sc.expect_min_concurrent == 50000


# ---------------------------------------------------------------------------
# SNMPSourceSpec: env-var expansion + bundle validation
# ---------------------------------------------------------------------------


def test_snmp_community_env_var_expansion(monkeypatch):
    """community=${VAR} is expanded from the env at validation time."""
    monkeypatch.setenv("STAGELAB_SNMP_COMMUNITY_FOO", "public")
    spec = SNMPSourceSpec(
        kind="snmp",
        name="test-src",
        host="192.168.1.1",
        community="${STAGELAB_SNMP_COMMUNITY_FOO}",
        oids=["1.3.6.1.2.1.1.1.0"],
    )
    assert spec.community == "public"


def test_snmp_community_missing_env_var_raises(monkeypatch):
    """community=${UNSET_VAR} raises ValidationError mentioning VARNAME but not the value."""
    monkeypatch.delenv("STAGELAB_SNMP_COMMUNITY_NOTSET", raising=False)
    with pytest.raises(ValidationError) as exc_info:
        SNMPSourceSpec(
            kind="snmp",
            name="test-src",
            host="192.168.1.1",
            community="${STAGELAB_SNMP_COMMUNITY_NOTSET}",
            oids=["1.3.6.1.2.1.1.1.0"],
        )
    err_str = str(exc_info.value)
    assert "STAGELAB_SNMP_COMMUNITY_NOTSET" in err_str
    assert "public" not in err_str


def test_snmp_unknown_bundle_rejected():
    """bundles containing an unknown name raises ValidationError mentioning the name and valid names."""
    with pytest.raises(ValidationError) as exc_info:
        SNMPSourceSpec(
            kind="snmp",
            name="test-src",
            host="192.168.1.1",
            community="public",
            oids=[],
            bundles=["node_traffic", "not-a-bundle"],
        )
    err_str = str(exc_info.value)
    assert "not-a-bundle" in err_str


# ---------------------------------------------------------------------------
# Endpoint role field tests
# ---------------------------------------------------------------------------


def test_endpoint_role_defaults_to_none():
    """Endpoint.role is None by default (back-compat: existing configs parse unchanged)."""
    ep = Endpoint(name="ep1", host="h1", mode="native", nic="eth0")
    assert ep.role is None


def test_endpoint_role_valid_slug():
    """A valid role slug is accepted and preserved."""
    ep = Endpoint(name="ep1", host="h1", mode="native", nic="eth0", role="wan-uplink")
    assert ep.role == "wan-uplink"


def test_endpoint_role_underscore_slug():
    """A role slug with underscores is accepted."""
    ep = Endpoint(name="ep1", host="h1", mode="native", nic="eth0", role="lan_downstream")
    assert ep.role == "lan_downstream"


def test_endpoint_role_invalid_raises():
    """An invalid role (contains '!') raises ValidationError."""
    with pytest.raises(ValidationError, match="role"):
        Endpoint(name="ep1", host="h1", mode="native", nic="eth0", role="invalid!")
