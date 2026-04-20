"""Pydantic StagelabConfig: YAML schema for hosts, DUT, endpoints, scenarios."""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Annotated, Any, Literal, Union

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_PCI_RE = re.compile(r"^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$")
_ENV_VAR_RE = re.compile(r"^\$\{([A-Z_][A-Z0-9_]*)\}$")
_SLUG_RE = re.compile(r"^[a-z0-9]+([-_][a-z0-9]+)*$")

# TRex multiplier grammar: "<number><unit>" or "<percent>%".
# Numbers: integer or decimal. Units (case-insensitive): bps, kbps, mbps,
# gbps, pps, kpps, mpps, or "%" for percent-of-line-rate.
_TREX_MULTIPLIER_RE = re.compile(
    r"^\d+(?:\.\d+)?(?:bps|kbps|mbps|gbps|pps|kpps|mpps|%)$",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Host
# ---------------------------------------------------------------------------


class Host(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    address: str
    work_dir: str = "/root/shorewall-nft"
    isolate_cores: list[int] = []
    hugepages_gib: int = 0


# ---------------------------------------------------------------------------
# DUT
# ---------------------------------------------------------------------------


class Dut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["external", "netns"]


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


class Endpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    host: str
    mode: Literal["probe", "native", "dpdk"]
    nic: str | None = None
    vlan: int | None = None
    ipv4: str | None = None
    ipv4_gw: str | None = None
    ipv6: str | None = None
    ipv6_gw: str | None = None
    rss_queues: int | None = None
    irq_affinity: list[int] = []
    bridge: str | None = None
    # --- Role-based endpoint binding ---
    # Optional logical role that lets catalogue fragments reference endpoints
    # without hard-coding endpoint names.  Recommended slugs:
    #   wan-uplink        — external network / backbone peer
    #   lan-downstream    — customer-zone behind the FW
    #   dmz-downstream    — DMZ zone, if distinct from LAN
    #   client / server   — generic traffic-direction (fallback)
    # Default None means "no role; cannot be resolved via role-lookup".
    role: str | None = None
    # --- DPDK-specific ---
    pci_addr: str | None = None            # "0000:01:00.0"
    dpdk_cores: list[int] = []             # CPU cores for DPDK poll mode
    hugepages_gib: int = 0                 # memory footprint
    trex_role: Literal["client", "server", ""] = ""
    # Derived field — operator must NOT set this in YAML.
    # Populated by StagelabConfig._assign_trex_port_ids after full config parse.
    trex_port_id: int | None = None

    @field_validator("vlan")
    @classmethod
    def _validate_vlan(cls, v: int | None) -> int | None:
        if v is not None and not (1 <= v <= 4094):
            raise ValueError(f"vlan must be in range 1..4094, got {v}")
        return v

    @field_validator("ipv4")
    @classmethod
    def _validate_ipv4(cls, v: str | None) -> str | None:
        if v is not None:
            try:
                ipaddress.ip_interface(v)
            except ValueError as exc:
                raise ValueError(f"invalid ipv4 interface address: {v!r}") from exc
        return v

    @field_validator("ipv4_gw")
    @classmethod
    def _validate_ipv4_gw(cls, v: str | None) -> str | None:
        if v is not None:
            try:
                ipaddress.ip_address(v)
            except ValueError as exc:
                raise ValueError(f"invalid ipv4_gw address: {v!r}") from exc
        return v

    @field_validator("ipv6")
    @classmethod
    def _validate_ipv6(cls, v: str | None) -> str | None:
        if v is not None:
            try:
                ipaddress.ip_interface(v)
            except ValueError as exc:
                raise ValueError(f"invalid ipv6 interface address: {v!r}") from exc
        return v

    @field_validator("ipv6_gw")
    @classmethod
    def _validate_ipv6_gw(cls, v: str | None) -> str | None:
        if v is not None:
            try:
                ipaddress.ip_address(v)
            except ValueError as exc:
                raise ValueError(f"invalid ipv6_gw address: {v!r}") from exc
        return v

    @field_validator("role")
    @classmethod
    def _validate_role(cls, v: str | None) -> str | None:
        if v is not None and not _SLUG_RE.match(v):
            raise ValueError(
                f"endpoint role {v!r} must match ^[a-z0-9]+([-_][a-z0-9]+)*$ "
                "(lowercase alphanumeric, hyphens or underscores only)"
            )
        return v

    @model_validator(mode="after")
    def _check_dpdk_fields(self) -> "Endpoint":
        if self.mode == "dpdk":
            if not self.pci_addr or not _PCI_RE.match(self.pci_addr):
                raise ValueError(
                    f"dpdk endpoint {self.name!r}: pci_addr must be set and match "
                    r"^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$, "
                    f"got {self.pci_addr!r}"
                )
            if not self.dpdk_cores:
                raise ValueError(
                    f"dpdk endpoint {self.name!r}: dpdk_cores must be non-empty"
                )
            if self.hugepages_gib < 1:
                raise ValueError(
                    f"dpdk endpoint {self.name!r}: hugepages_gib must be >= 1, "
                    f"got {self.hugepages_gib}"
                )
            if self.trex_role not in {"client", "server"}:
                raise ValueError(
                    f"dpdk endpoint {self.name!r}: trex_role must be 'client' or "
                    f"'server', got {self.trex_role!r}"
                )
            if self.bridge is not None:
                raise ValueError(
                    f"dpdk endpoint {self.name!r}: bridge must not be set "
                    "(DPDK endpoints do not use Linux bridges)"
                )
        elif self.mode in {"probe", "native"}:
            _dpdk_extras = {
                "pci_addr": self.pci_addr,
                "dpdk_cores": self.dpdk_cores,
                "hugepages_gib": self.hugepages_gib,
                "trex_role": self.trex_role,
            }
            set_dpdk = {
                k for k, v in _dpdk_extras.items()
                if v not in (None, [], 0, "")
            }
            if set_dpdk:
                raise ValueError(
                    f"{self.mode} endpoint {self.name!r}: DPDK-specific fields "
                    f"{sorted(set_dpdk)} must not be set on non-dpdk endpoints"
                )
        return self


# ---------------------------------------------------------------------------
# Standards-layer helpers
# ---------------------------------------------------------------------------


def _validate_test_id_slug(v: str) -> str:
    """Validate that *v* is a slug: lowercase alphanumeric with hyphens or underscores."""
    if not _SLUG_RE.match(v):
        raise ValueError(
            f"test_id/standard_refs slug {v!r} must match ^[a-z0-9]+([-_][a-z0-9]+)*$ "
            "(lowercase alphanumeric, hyphens or underscores only)"
        )
    return v


# ---------------------------------------------------------------------------
# Scenarios (discriminated union on `kind`)
# ---------------------------------------------------------------------------


class ThroughputScenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: Literal["throughput"]
    source: str
    sink: str
    proto: Literal["tcp", "udp"]
    duration_s: int
    parallel: int
    expect_min_gbps: float
    measure_latency: bool = False  # if True, extract per-interval TCP RTT from iperf3 JSON
    test_id: str | None = None
    standard_refs: list[str] = []
    acceptance_criteria: dict[str, Any] = {}

    @field_validator("test_id")
    @classmethod
    def _validate_test_id(cls, v: str | None) -> str | None:
        if v is not None:
            _validate_test_id_slug(v)
        return v

    @field_validator("standard_refs")
    @classmethod
    def _validate_standard_refs(cls, v: list[str]) -> list[str]:
        for item in v:
            _validate_test_id_slug(item)
        if len(set(v)) != len(v):
            raise ValueError("standard_refs must not contain duplicates")
        return v


class ConnStormScenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: Literal["conn_storm"]
    source: str
    sink: str
    target_conns: int
    rate_per_s: int
    hold_s: int
    test_id: str | None = None
    standard_refs: list[str] = []
    acceptance_criteria: dict[str, Any] = {}

    @field_validator("test_id")
    @classmethod
    def _validate_test_id(cls, v: str | None) -> str | None:
        if v is not None:
            _validate_test_id_slug(v)
        return v

    @field_validator("standard_refs")
    @classmethod
    def _validate_standard_refs(cls, v: list[str]) -> list[str]:
        for item in v:
            _validate_test_id_slug(item)
        if len(set(v)) != len(v):
            raise ValueError("standard_refs must not contain duplicates")
        return v


class RuleScanScenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: Literal["rule_scan"]
    source: str
    target_subnet: str
    random_count: int
    test_id: str | None = None
    standard_refs: list[str] = []
    acceptance_criteria: dict[str, Any] = {}

    @field_validator("test_id")
    @classmethod
    def _validate_test_id(cls, v: str | None) -> str | None:
        if v is not None:
            _validate_test_id_slug(v)
        return v

    @field_validator("standard_refs")
    @classmethod
    def _validate_standard_refs(cls, v: list[str]) -> list[str]:
        for item in v:
            _validate_test_id_slug(item)
        if len(set(v)) != len(v):
            raise ValueError("standard_refs must not contain duplicates")
        return v


class TuningSweepScenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: Literal["tuning_sweep"]
    source: str                         # endpoint name (native-mode)
    sink: str                           # endpoint name (native-mode)
    proto: Literal["tcp", "udp"] = "tcp"
    duration_per_point_s: int = 2
    # Grid axes — each is a list of values; runner does Cartesian product:
    rss_queues: list[int] = []          # iface RX queues to try; [] = skip axis
    rmem_max: list[int] = []            # bytes; [] = skip axis
    wmem_max: list[int] = []            # bytes; [] = skip axis
    test_id: str | None = None
    standard_refs: list[str] = []
    acceptance_criteria: dict[str, Any] = {}

    @field_validator("test_id")
    @classmethod
    def _validate_test_id(cls, v: str | None) -> str | None:
        if v is not None:
            _validate_test_id_slug(v)
        return v

    @field_validator("standard_refs")
    @classmethod
    def _validate_standard_refs(cls, v: list[str]) -> list[str]:
        for item in v:
            _validate_test_id_slug(item)
        if len(set(v)) != len(v):
            raise ValueError("standard_refs must not contain duplicates")
        return v


class ThroughputDpdkScenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: Literal["throughput_dpdk"]
    source: str                         # dpdk endpoint name (TRex TX side)
    sink: str                           # dpdk endpoint name (TRex RX / loopback)
    proto: Literal["tcp", "udp"] = "udp"
    duration_s: int = 10
    multiplier: str = "10gbps"          # TRex DSL: "50%", "1000kpps", "5gbps", etc.
    packet_size_b: int = 64             # for synthetic streams
    pcap_file: str = ""                 # optional replay pcap (absolute path)
    test_id: str | None = None
    standard_refs: list[str] = []
    acceptance_criteria: dict[str, Any] = {}

    @field_validator("test_id")
    @classmethod
    def _validate_test_id(cls, v: str | None) -> str | None:
        if v is not None:
            _validate_test_id_slug(v)
        return v

    @field_validator("standard_refs")
    @classmethod
    def _validate_standard_refs(cls, v: list[str]) -> list[str]:
        for item in v:
            _validate_test_id_slug(item)
        if len(set(v)) != len(v):
            raise ValueError("standard_refs must not contain duplicates")
        return v

    @field_validator("multiplier")
    @classmethod
    def _check_multiplier(cls, v: str) -> str:
        if not _TREX_MULTIPLIER_RE.match(v):
            raise ValueError(
                f"invalid TRex multiplier {v!r}; expected forms like "
                "'10gbps', '50%', '1.5mpps', '1000bps' (units: bps, kbps, "
                "mbps, gbps, pps, kpps, mpps, %; case-insensitive)"
            )
        return v


class ConnStormAstfScenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: Literal["conn_storm_astf"]
    source: str                         # dpdk endpoint (ASTF-client side)
    sink: str                           # dpdk endpoint (ASTF-server side)
    profile_py: str                     # absolute path to ASTF profile
    duration_s: int = 30
    multiplier: float = 1.0
    expect_min_concurrent: int = 0      # advisor signal threshold
    test_id: str | None = None
    standard_refs: list[str] = []
    acceptance_criteria: dict[str, Any] = {}

    @field_validator("test_id")
    @classmethod
    def _validate_test_id(cls, v: str | None) -> str | None:
        if v is not None:
            _validate_test_id_slug(v)
        return v

    @field_validator("standard_refs")
    @classmethod
    def _validate_standard_refs(cls, v: list[str]) -> list[str]:
        for item in v:
            _validate_test_id_slug(item)
        if len(set(v)) != len(v):
            raise ValueError("standard_refs must not contain duplicates")
        return v


class SynFloodDosScenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: Literal["dos_syn_flood"]
    source: str                            # endpoint name (must be mode=dpdk)
    sink: str                              # endpoint name (must be mode=dpdk)
    duration_s: int = 10
    rate_pps: int                          # aggregate SYN pps
    src_ip_range: str                      # CIDR for spoofed src IPs
    dst_port_range: str = "80,443"         # comma-list or single port/range
    expect_max_passed_ratio: float = 0.05  # pass if ≤5% of SYNs reach sink
    baseline_window_s: float = 10.0        # sample metrics this many seconds BEFORE DoS phase
    dos_window_s: float = 10.0             # sample metrics this many seconds DURING/AFTER DoS
    test_id: str | None = None
    standard_refs: list[str] = []
    acceptance_criteria: dict[str, Any] = {}

    @field_validator("baseline_window_s", "dos_window_s")
    @classmethod
    def _check_window_positive(cls, v: float) -> float:
        if v <= 0:
            raise ValueError(f"window duration must be > 0, got {v}")
        return v

    @field_validator("test_id")
    @classmethod
    def _validate_test_id(cls, v: str | None) -> str | None:
        if v is not None:
            _validate_test_id_slug(v)
        return v

    @field_validator("standard_refs")
    @classmethod
    def _validate_standard_refs(cls, v: list[str]) -> list[str]:
        for item in v:
            _validate_test_id_slug(item)
        if len(set(v)) != len(v):
            raise ValueError("standard_refs must not contain duplicates")
        return v

    @field_validator("src_ip_range")
    @classmethod
    def _check_cidr(cls, v: str) -> str:
        ipaddress.ip_network(v, strict=False)  # raises on malformed
        return v

    @field_validator("rate_pps")
    @classmethod
    def _check_rate_cap(cls, v: int) -> int:
        from .dos_safety import rate_cap_pps
        cap = rate_cap_pps()
        if v > cap:
            raise ValueError(
                f"rate_pps={v} exceeds STAGELAB_DOS_RATE_CAP_PPS={cap}"
            )
        return v


class DnsDosScenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: Literal["dos_dns_query"]
    source: str                            # endpoint name (mode=dpdk)
    sink: str                              # endpoint name (mode=dpdk)
    duration_s: int = 10
    queries_per_s: int                     # aggregate QPS
    query_name_pattern: Literal["random", "fixed", "amplification"] = "random"
    target_resolver: str                   # IPv4 of the DNS server
    fixed_qname: str = "example.com"       # used when pattern=fixed
    test_id: str | None = None
    standard_refs: list[str] = []
    acceptance_criteria: dict[str, Any] = {}

    @field_validator("test_id")
    @classmethod
    def _validate_test_id(cls, v: str | None) -> str | None:
        if v is not None:
            _validate_test_id_slug(v)
        return v

    @field_validator("standard_refs")
    @classmethod
    def _validate_standard_refs(cls, v: list[str]) -> list[str]:
        for item in v:
            _validate_test_id_slug(item)
        if len(set(v)) != len(v):
            raise ValueError("standard_refs must not contain duplicates")
        return v

    @field_validator("target_resolver")
    @classmethod
    def _check_ip(cls, v: str) -> str:
        ipaddress.ip_address(v)
        return v

    @field_validator("queries_per_s")
    @classmethod
    def _check_rate_cap(cls, v: int) -> int:
        from .dos_safety import rate_cap_pps
        cap = rate_cap_pps()
        if v > cap:
            raise ValueError(
                f"queries_per_s={v} exceeds STAGELAB_DOS_RATE_CAP_PPS={cap}"
            )
        return v


class HalfOpenDosScenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: Literal["dos_half_open"]
    source: str                           # endpoint name (mode=dpdk)
    sink: str                             # endpoint name (mode=dpdk)
    duration_s: int = 30
    target_conns: int                     # concurrent half-open TCP conns to reach
    open_rate_per_s: int                  # new-connection rate
    dst_port: int = 80
    test_id: str | None = None
    standard_refs: list[str] = []
    acceptance_criteria: dict[str, Any] = {}

    @field_validator("test_id")
    @classmethod
    def _validate_test_id(cls, v: str | None) -> str | None:
        if v is not None:
            _validate_test_id_slug(v)
        return v

    @field_validator("standard_refs")
    @classmethod
    def _validate_standard_refs(cls, v: list[str]) -> list[str]:
        for item in v:
            _validate_test_id_slug(item)
        if len(set(v)) != len(v):
            raise ValueError("standard_refs must not contain duplicates")
        return v

    @field_validator("dst_port")
    @classmethod
    def _check_port(cls, v: int) -> int:
        if not 1 <= v <= 65535:
            raise ValueError(f"dst_port={v} out of range 1-65535")
        return v

    @field_validator("open_rate_per_s")
    @classmethod
    def _check_rate_cap(cls, v: int) -> int:
        from .dos_safety import rate_cap_pps
        cap = rate_cap_pps()
        if v > cap:
            raise ValueError(
                f"open_rate_per_s={v} exceeds STAGELAB_DOS_RATE_CAP_PPS={cap}"
            )
        return v


class ConntrackOverflowScenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: Literal["conntrack_overflow"]
    source: str              # endpoint name (native or dpdk)
    sink: str                # endpoint name
    fw_host: str             # SSH target for conntrack inspection
    duration_s: int = 60
    rate_new_per_s: int = 10000
    expect_table_fill_pct_min: int = 95
    expect_no_new_conntracks_when_full: bool = True
    baseline_window_s: float = 10.0   # sample metrics this many seconds BEFORE DoS phase
    dos_window_s: float = 10.0        # sample metrics this many seconds DURING/AFTER DoS

    test_id: str | None = None
    standard_refs: list[str] = []
    acceptance_criteria: dict[str, Any] = {}

    @field_validator("baseline_window_s", "dos_window_s")
    @classmethod
    def _check_window_positive(cls, v: float) -> float:
        if v <= 0:
            raise ValueError(f"window duration must be > 0, got {v}")
        return v

    @field_validator("test_id")
    @classmethod
    def _validate_test_id(cls, v: str | None) -> str | None:
        if v is not None:
            _validate_test_id_slug(v)
        return v

    @field_validator("standard_refs")
    @classmethod
    def _validate_standard_refs(cls, v: list[str]) -> list[str]:
        for item in v:
            _validate_test_id_slug(item)
        if len(set(v)) != len(v):
            raise ValueError("standard_refs must not contain duplicates")
        return v

    @field_validator("expect_table_fill_pct_min")
    @classmethod
    def _check_fill_pct(cls, v: int) -> int:
        if not 1 <= v <= 100:
            raise ValueError(f"expect_table_fill_pct_min={v} must be in range 1-100")
        return v


class RuleCoverageMatrixScenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: Literal["rule_coverage_matrix"]
    source: str                          # endpoint name (probe or native)
    zone_subnets: dict[str, str]         # zone_name -> CIDR, e.g. {"lan": "10.0.10.0/24"}
    protos: list[Literal["tcp", "udp", "icmp"]] = ["tcp", "udp", "icmp"]
    tcp_ports: list[int] = [22, 80, 443]
    udp_ports: list[int] = [53, 123]
    probe_count_per_tuple: int = 1       # how many probes per (src-zone, dst-zone, proto, port)
    test_id: str | None = None
    standard_refs: list[str] = []
    acceptance_criteria: dict[str, Any] = {}

    @field_validator("test_id")
    @classmethod
    def _validate_test_id(cls, v: str | None) -> str | None:
        if v is not None:
            _validate_test_id_slug(v)
        return v

    @field_validator("standard_refs")
    @classmethod
    def _validate_standard_refs(cls, v: list[str]) -> list[str]:
        for item in v:
            _validate_test_id_slug(item)
        if len(set(v)) != len(v):
            raise ValueError("standard_refs must not contain duplicates")
        return v

    @field_validator("zone_subnets")
    @classmethod
    def _check_subnets(cls, v: dict[str, str]) -> dict[str, str]:
        for zone, cidr in v.items():
            ipaddress.ip_network(cidr, strict=False)  # raises on malformed
            if "_" in zone:
                raise ValueError(f"zone name {zone!r} contains '_' (not Shorewall-compatible)")
        return v


class StatefulHelperFtpScenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: Literal["stateful_helper_ftp"]
    source: str                           # endpoint name (native)
    sink: str                             # endpoint name (native) — hosts vsftpd
    ftp_port: int = 21                    # control channel port
    mode: Literal["active", "passive"] = "passive"
    user: str = "ftpuser"
    password: str = "ftpuser"
    test_file: str = "/tmp/stagelab-ftp-test.txt"  # expected on vsftpd
    expect_data_connection: bool = True    # True = data xfer must succeed
    test_id: str | None = None
    standard_refs: list[str] = []
    acceptance_criteria: dict[str, Any] = {}

    @field_validator("test_id")
    @classmethod
    def _validate_test_id(cls, v: str | None) -> str | None:
        if v is not None:
            _validate_test_id_slug(v)
        return v

    @field_validator("standard_refs")
    @classmethod
    def _validate_standard_refs(cls, v: list[str]) -> list[str]:
        for item in v:
            _validate_test_id_slug(item)
        if len(set(v)) != len(v):
            raise ValueError("standard_refs must not contain duplicates")
        return v

    @field_validator("ftp_port")
    @classmethod
    def _check_port(cls, v: int) -> int:
        if not 1 <= v <= 65535:
            raise ValueError(f"ftp_port={v} out of range 1–65535")
        return v


class EvasionProbesScenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: Literal["evasion_probes"]
    source: str                             # endpoint name (probe mode preferred)
    target_ip: str                          # destination IP
    probe_types: list[Literal[
        "tcp_null", "tcp_xmas", "tcp_fin_no_syn",
        "tcp_shrinking_window",
        "ip_spoof", "ip_overlap_fragments",
        "udp_malformed_checksum",
    ]] = [
        "tcp_null", "tcp_xmas", "tcp_fin_no_syn",
        "ip_spoof", "udp_malformed_checksum",
    ]
    spoof_src_ip: str = "10.255.255.255"    # used for ip_spoof probes
    target_port: int = 80
    test_id: str | None = None
    standard_refs: list[str] = []
    acceptance_criteria: dict[str, Any] = {}

    @field_validator("test_id")
    @classmethod
    def _validate_test_id(cls, v: str | None) -> str | None:
        if v is not None:
            _validate_test_id_slug(v)
        return v

    @field_validator("standard_refs")
    @classmethod
    def _validate_standard_refs(cls, v: list[str]) -> list[str]:
        for item in v:
            _validate_test_id_slug(item)
        if len(set(v)) != len(v):
            raise ValueError("standard_refs must not contain duplicates")
        return v

    @field_validator("target_ip", "spoof_src_ip")
    @classmethod
    def _check_ip(cls, v: str) -> str:
        ipaddress.ip_address(v)
        return v

    @field_validator("target_port")
    @classmethod
    def _check_port(cls, v: int) -> int:
        if not 1 <= v <= 65535:
            raise ValueError(f"target_port={v} out of range 1–65535")
        return v


class ReloadAtomicityScenario(BaseModel):
    """Reload-atomicity drill: runs a long TCP stream through the FW, then
    mid-stream triggers ``shorewall-nft restart`` via SSH on the FW host.

    Prerequisite: the agent host must have passwordless SSH access to
    ``fw_host`` (e.g. via an authorized_keys entry for root).
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    kind: Literal["reload_atomicity"]
    source: str                           # endpoint name (native)
    sink: str                             # endpoint name (native)
    fw_host: str                          # user@host of FW (to SSH for reload)
    reload_command: str = "shorewall-nft restart /etc/shorewall46"
    duration_s: int = 60                  # total stream length
    reload_at_s: int = 20                 # fire the reload this many seconds in
    max_retrans_during_reload: int = 100  # pass threshold
    test_id: str | None = None
    standard_refs: list[str] = []
    acceptance_criteria: dict[str, Any] = {}

    @field_validator("test_id")
    @classmethod
    def _validate_test_id(cls, v: str | None) -> str | None:
        if v is not None:
            _validate_test_id_slug(v)
        return v

    @field_validator("standard_refs")
    @classmethod
    def _validate_standard_refs(cls, v: list[str]) -> list[str]:
        for item in v:
            _validate_test_id_slug(item)
        if len(set(v)) != len(v):
            raise ValueError("standard_refs must not contain duplicates")
        return v

    @field_validator("reload_at_s")
    @classmethod
    def _check_reload_timing(cls, v: int, info) -> int:
        dur = info.data.get("duration_s", 60)
        if v < 2 or v >= dur - 2:
            raise ValueError(
                f"reload_at_s={v} must be ≥ 2 and ≤ duration_s-2 ({dur - 2})"
            )
        return v


class LongFlowSurvivalScenario(BaseModel):
    """Long-flow survivability drill.

    Temporarily lowers a conntrack timeout sysctl on the FW via SSH, then
    runs a long iperf3 TCP stream and checks whether the flow survived (or
    died, if that is what the scenario expects).

    Prerequisite: the agent host must have passwordless SSH access to
    ``fw_host``.

    **The sysctl change is runtime-only (non-persistent).  Operator is
    responsible for reverting it after the run or rebooting the FW.**
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    kind: Literal["long_flow_survival"]
    source: str
    sink: str
    fw_host: str                              # user@host of FW — SSH target
    duration_s: int = 300                      # 5 minutes default
    sysctl_key: str = "net.netfilter.nf_conntrack_tcp_timeout_established"
    sysctl_value: int = 240                    # 4 minutes (less than duration_s → flow should die)
    expect_flow_dies: bool = False             # False = flow should SURVIVE the full duration
    test_id: str | None = None
    standard_refs: list[str] = []
    acceptance_criteria: dict[str, Any] = {}

    @field_validator("test_id")
    @classmethod
    def _validate_test_id(cls, v: str | None) -> str | None:
        if v is not None:
            _validate_test_id_slug(v)
        return v

    @field_validator("standard_refs")
    @classmethod
    def _validate_standard_refs(cls, v: list[str]) -> list[str]:
        for item in v:
            _validate_test_id_slug(item)
        if len(set(v)) != len(v):
            raise ValueError("standard_refs must not contain duplicates")
        return v

    @field_validator("sysctl_key")
    @classmethod
    def _check_sysctl_key(cls, v: str) -> str:
        if not v.startswith("net.netfilter.nf_conntrack_"):
            raise ValueError(
                f"sysctl_key={v!r} must start with 'net.netfilter.nf_conntrack_' "
                "— only conntrack timeouts are in-scope for this scenario"
            )
        return v


class HaFailoverDrillScenario(BaseModel):
    """VRRP HA failover drill.

    Establishes a long-running TCP stream through the FW HA pair, stops a
    service (keepalived, bird, frr) on the primary FW host, measures
    downtime until traffic flows again via the secondary, then restarts the
    service on the primary to restore normal operation.

    All FW operations are runtime-only (``systemctl stop/start``).
    No disk writes, no ``systemctl enable/disable``.

    When ``vrrp_snmp_source`` is set to a list of two metrics source names
    ``[primary_source, secondary_source]``, the runner emits an extra
    ``poll_vrrp_state`` AgentCommand that polls VRRP state on both FW nodes
    via SNMP for the scenario duration, yielding precise downtime measurements.
    Falls back to the retransmit heuristic when not set.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    kind: Literal["ha_failover_drill"]
    source: str                                     # endpoint name (native)
    sink: str                                       # endpoint name (native)
    primary_fw_host: str                            # user@host of FW to stop service on
    secondary_fw_host: str                          # user@host — read-only conntrack query after drill
    duration_s: int = 90                            # total stream length
    stop_at_s: int = 20                             # seconds in, stop service
    restart_at_s: int = 60                          # seconds in, restart service
    service_name: str = "keepalived"                # limited vocabulary, see validator
    max_downtime_s: float = 5.0                     # flow must recover within this
    # vrrp_snmp_source: list of exactly 2 metrics source names [primary, secondary].
    # When set, enables VRRP-SNMP polling for precise downtime measurement.
    vrrp_snmp_source: list[str] | None = None
    vrrp_poll_interval_ms: int = 200                # must be >= 50 (pysnmp overhead floor)
    vrrp_instance_name: str | None = None           # if None, pick first instance
    test_id: str | None = None
    standard_refs: list[str] = []
    acceptance_criteria: dict[str, Any] = {}

    @field_validator("test_id")
    @classmethod
    def _validate_test_id(cls, v: str | None) -> str | None:
        if v is not None:
            _validate_test_id_slug(v)
        return v

    @field_validator("standard_refs")
    @classmethod
    def _validate_standard_refs(cls, v: list[str]) -> list[str]:
        for item in v:
            _validate_test_id_slug(item)
        if len(set(v)) != len(v):
            raise ValueError("standard_refs must not contain duplicates")
        return v

    @field_validator("vrrp_snmp_source")
    @classmethod
    def _check_vrrp_snmp_source(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        if len(v) != 2:
            raise ValueError(
                f"vrrp_snmp_source must be a list of exactly 2 source names "
                f"[primary, secondary], got {len(v)} entries"
            )
        return v

    @field_validator("vrrp_poll_interval_ms")
    @classmethod
    def _check_poll_interval(cls, v: int) -> int:
        if v < 50:
            raise ValueError(
                f"vrrp_poll_interval_ms={v} must be >= 50 (pysnmp overhead floor)"
            )
        return v

    @field_validator("service_name")
    @classmethod
    def _check_service(cls, v: str) -> str:
        # Lock the service name to a known-safe set — prevents the SSH
        # handler from being used to stop arbitrary services on the FW.
        _ALLOWED = {"keepalived", "bird", "frr"}
        if v not in _ALLOWED:
            raise ValueError(f"service_name={v!r} not in allowed set {_ALLOWED}")
        return v

    @field_validator("restart_at_s")
    @classmethod
    def _check_ordering(cls, v: int, info) -> int:
        dur = info.data.get("duration_s", 90)
        stop = info.data.get("stop_at_s", 20)
        if v <= stop:
            raise ValueError(f"restart_at_s={v} must be > stop_at_s={stop}")
        if v >= dur - 5:
            raise ValueError(f"restart_at_s={v} must leave >= 5 s tail (duration_s={dur})")
        return v


Scenario = Annotated[
    Union[
        ThroughputScenario,
        ConnStormScenario,
        RuleScanScenario,
        TuningSweepScenario,
        ThroughputDpdkScenario,
        ConnStormAstfScenario,
        SynFloodDosScenario,
        DnsDosScenario,
        HalfOpenDosScenario,
        ConntrackOverflowScenario,
        RuleCoverageMatrixScenario,
        StatefulHelperFtpScenario,
        EvasionProbesScenario,
        ReloadAtomicityScenario,
        LongFlowSurvivalScenario,
        HaFailoverDrillScenario,
    ],
    Field(discriminator="kind"),
]


# ---------------------------------------------------------------------------
# MetricsSpec
# ---------------------------------------------------------------------------

_MetricName = Literal["nft_counters", "conntrack_stats", "nic_ethtool", "cpu_softirq"]


class PrometheusSourceSpec(BaseModel):
    kind: Literal["prometheus"]
    name: str
    url: str
    timeout_s: float = 5.0
    metric_prefix_allow: list[str] = []
    model_config = ConfigDict(extra="forbid")


def _expand_env_var(value: str, field_name: str) -> str:
    """Expand ``${VARNAME}`` syntax; pass through literals unchanged.

    Raises ValueError if the env var is unset.  The resolved value is
    never included in the error message.
    """
    m = _ENV_VAR_RE.match(value)
    if m is None:
        return value
    varname = m.group(1)
    resolved = os.environ.get(varname)
    if resolved is None:
        raise ValueError(
            f"{field_name}: env var ${{{varname}}} is not set"
        )
    return resolved


class SNMPSourceSpec(BaseModel):
    kind: Literal["snmp"]
    name: str
    host: str
    community: str
    oids: list[str] = []
    port: int = 161
    timeout_s: float = 3.0
    bundles: list[str] = ["node_traffic"]
    model_config = ConfigDict(extra="forbid")

    @field_validator("community", mode="before")
    @classmethod
    def _expand_community(cls, v: str) -> str:
        return _expand_env_var(v, "community")

    @field_validator("host", mode="before")
    @classmethod
    def _expand_host(cls, v: str) -> str:
        return _expand_env_var(v, "host")

    @field_validator("bundles")
    @classmethod
    def _validate_bundles(cls, v: list[str]) -> list[str]:
        from .snmp_oids import BUNDLES
        valid = sorted(BUNDLES.keys())
        unknown = [name for name in v if name not in BUNDLES]
        if unknown:
            raise ValueError(
                f"unknown bundle name(s) {unknown!r}; "
                f"valid names: {valid}"
            )
        return v


class NftSSHSourceSpec(BaseModel):
    kind: Literal["nft_ssh"]
    name: str
    ssh_target: str
    timeout_s: float = 10.0
    model_config = ConfigDict(extra="forbid")


SourceSpec = Annotated[
    Union[PrometheusSourceSpec, SNMPSourceSpec, NftSSHSourceSpec],
    Field(discriminator="kind"),
]


class MetricsSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    poll_interval_s: int = 1
    collect: list[_MetricName] = []
    sources: list[SourceSpec] = []


# ---------------------------------------------------------------------------
# ReportSpec
# ---------------------------------------------------------------------------


class ReportSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    output_dir: str
    keep_pcaps: Literal["none", "failed_only", "all"] = "failed_only"


# ---------------------------------------------------------------------------
# StagelabConfig (top-level, with referential integrity)
# ---------------------------------------------------------------------------


class StagelabConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hosts: list[Host]
    dut: Dut
    endpoints: list[Endpoint]
    scenarios: list[Scenario]
    metrics: MetricsSpec = MetricsSpec()
    report: ReportSpec
    dos_target_allowlist: list[str] = Field(default_factory=list)

    @field_validator("dos_target_allowlist")
    @classmethod
    def _validate_dos_allowlist(cls, v: list[str]) -> list[str]:
        for entry in v:
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError as exc:
                raise ValueError(
                    f"dos_target_allowlist: invalid CIDR/IP entry {entry!r}: {exc}"
                ) from exc
        return v

    @model_validator(mode="after")
    def _check_integrity(self) -> "StagelabConfig":
        # 1. Unique host names
        host_names = [h.name for h in self.hosts]
        if len(host_names) != len(set(host_names)):
            seen: set[str] = set()
            for n in host_names:
                if n in seen:
                    raise ValueError(f"duplicate host name: {n!r}")
                seen.add(n)

        # 2. Unique endpoint names
        ep_names = [e.name for e in self.endpoints]
        if len(ep_names) != len(set(ep_names)):
            seen = set()
            for n in ep_names:
                if n in seen:
                    raise ValueError(f"duplicate endpoint name: {n!r}")
                seen.add(n)

        # 3. Unique scenario IDs
        sc_ids = [s.id for s in self.scenarios]
        if len(sc_ids) != len(set(sc_ids)):
            seen = set()
            for n in sc_ids:
                if n in seen:
                    raise ValueError(f"duplicate scenario id: {n!r}")
                seen.add(n)

        host_name_set = set(host_names)
        ep_name_set = set(ep_names)

        # 4. Endpoint.host must exist in hosts
        for ep in self.endpoints:
            if ep.host not in host_name_set:
                raise ValueError(
                    f"endpoint {ep.name!r} references unknown host {ep.host!r}"
                )

        # 5. Scenario source/sink must exist in endpoints
        ep_mode_map = {ep.name: ep.mode for ep in self.endpoints}
        for sc in self.scenarios:
            if sc.source not in ep_name_set:
                raise ValueError(
                    f"scenario {sc.id!r} source {sc.source!r} not found in endpoints"
                )
            if hasattr(sc, "sink") and sc.sink not in ep_name_set:  # type: ignore[union-attr]
                raise ValueError(
                    f"scenario {sc.id!r} sink {sc.sink!r} not found in endpoints"
                )

        # 5b. throughput_dpdk and conn_storm_astf require dpdk endpoints
        for sc in self.scenarios:
            if sc.kind in {"throughput_dpdk", "conn_storm_astf"}:
                if ep_mode_map.get(sc.source) != "dpdk":
                    raise ValueError(
                        f"scenario {sc.id!r} ({sc.kind}): source {sc.source!r} "
                        "must reference a dpdk endpoint"
                    )
                if ep_mode_map.get(sc.sink) != "dpdk":  # type: ignore[union-attr]
                    raise ValueError(
                        f"scenario {sc.id!r} ({sc.kind}): sink {sc.sink!r} "  # type: ignore[union-attr]
                        "must reference a dpdk endpoint"
                    )

        # 5c. dos_syn_flood: sink (and source if it has an ipv4) must be in
        #     dos_target_allowlist.
        #     dos_dns_query: target_resolver must be in dos_target_allowlist.
        #     dos_half_open: sink endpoint ipv4 (if any) must be in dos_target_allowlist.
        for sc in self.scenarios:
            if sc.kind == "dos_dns_query":
                if not _is_dos_target_allowed(sc.target_resolver, self.dos_target_allowlist):  # type: ignore[union-attr]
                    raise ValueError(
                        f"scenario {sc.id!r} dos_dns_query: target_resolver "
                        f"{sc.target_resolver!r} is not in dos_target_allowlist"  # type: ignore[union-attr]
                    )
        for sc in self.scenarios:
            if sc.kind == "dos_half_open":
                sink_ep = next(
                    (ep for ep in self.endpoints if ep.name == sc.sink), None  # type: ignore[union-attr]
                )
                if sink_ep is not None and sink_ep.ipv4 is not None:
                    sink_ip = sink_ep.ipv4.split("/")[0]
                    if not _is_dos_target_allowed(sink_ip, self.dos_target_allowlist):
                        raise ValueError(
                            f"scenario {sc.id!r} dos_half_open: sink endpoint "
                            f"{sc.sink!r} ip {sink_ip!r} is not in "  # type: ignore[union-attr]
                            "dos_target_allowlist"
                        )
        for sc in self.scenarios:
            if sc.kind == "dos_syn_flood":
                sink_ep = next(
                    (ep for ep in self.endpoints if ep.name == sc.sink), None
                )
                if sink_ep is not None and sink_ep.ipv4 is not None:
                    sink_ip = sink_ep.ipv4.split("/")[0]
                    if not _is_dos_target_allowed(sink_ip, self.dos_target_allowlist):
                        raise ValueError(
                            f"scenario {sc.id!r} dos_syn_flood: sink endpoint "
                            f"{sc.sink!r} ip {sink_ip!r} is not in "
                            "dos_target_allowlist"
                        )
                src_ep = next(
                    (ep for ep in self.endpoints if ep.name == sc.source), None
                )
                if src_ep is not None and src_ep.ipv4 is not None:
                    src_ip = src_ep.ipv4.split("/")[0]
                    if not _is_dos_target_allowed(src_ip, self.dos_target_allowlist):
                        raise ValueError(
                            f"scenario {sc.id!r} dos_syn_flood: source endpoint "
                            f"{sc.source!r} ip {src_ip!r} is not in "
                            "dos_target_allowlist"
                        )

        # 6. Disjoint-mode rule: same (host, nic) cannot mix probe and native
        probe_nics: set[tuple[str, str]] = set()
        native_nics: set[tuple[str, str]] = set()
        for ep in self.endpoints:
            if ep.nic is None:
                continue
            key = (ep.host, ep.nic)
            if ep.mode == "probe":
                probe_nics.add(key)
            elif ep.mode == "native":
                native_nics.add(key)
        overlap = probe_nics & native_nics
        if overlap:
            host, nic = next(iter(overlap))
            raise ValueError(
                f"NIC {nic!r} on host {host!r} is used by both probe and native endpoints"
            )

        # 7. Probe endpoints must set bridge; native endpoints must NOT set bridge
        #    Native endpoints must set nic + vlan + ipv4
        #    DPDK endpoints are validated by the Endpoint model_validator (skipped here)
        for ep in self.endpoints:
            if ep.mode == "probe":
                if ep.bridge is None:
                    raise ValueError(
                        f"probe endpoint {ep.name!r} must set 'bridge'"
                    )
            elif ep.mode == "native":
                if ep.bridge is not None:
                    raise ValueError(
                        f"native endpoint {ep.name!r} must not set 'bridge'"
                    )
                if ep.nic is None:
                    raise ValueError(
                        f"native endpoint {ep.name!r} must set 'nic'"
                    )
                if ep.vlan is None:
                    raise ValueError(
                        f"native endpoint {ep.name!r} must set 'vlan'"
                    )
                if ep.ipv4 is None:
                    raise ValueError(
                        f"native endpoint {ep.name!r} must set 'ipv4'"
                    )
            # mode == "dpdk": validated by Endpoint._check_dpdk_fields

        # 8. (host, nic, vlan) must be unique — two endpoints cannot claim the
        #    same VLAN on the same NIC on the same host
        seen_nic_vlan: set[tuple[str, str, int]] = set()
        for ep in self.endpoints:
            if ep.nic is None or ep.vlan is None:
                continue
            key3 = (ep.host, ep.nic, ep.vlan)
            if key3 in seen_nic_vlan:
                raise ValueError(
                    f"duplicate (host={ep.host!r}, nic={ep.nic!r}, vlan={ep.vlan}) "
                    f"for endpoint {ep.name!r}"
                )
            seen_nic_vlan.add(key3)

        # 9. DPDK: (host, pci_addr) must be unique — two DPDK endpoints on
        #    the same host cannot bind the same PCI device
        seen_pci: set[tuple[str, str]] = set()
        for ep in self.endpoints:
            if ep.mode != "dpdk" or ep.pci_addr is None:
                continue
            key_pci = (ep.host, ep.pci_addr)
            if key_pci in seen_pci:
                raise ValueError(
                    f"duplicate pci_addr {ep.pci_addr!r} on host {ep.host!r} "
                    f"for endpoint {ep.name!r}; two DPDK endpoints cannot bind "
                    "the same PCI device"
                )
            seen_pci.add(key_pci)

        # 10. Cross-mode NIC exclusion (best-effort / exact: pci_addr literal
        #     match against nic field).  Full NIC<->PCI mapping is operator
        #     responsibility; only the (host, pci_addr) uniqueness above is
        #     enforced exactly.  If a kernel endpoint's nic field is literally
        #     equal to a DPDK endpoint's pci_addr on the same host, reject it
        #     as a clear operator error.
        dpdk_pci_by_host: dict[str, set[str]] = {}
        for ep in self.endpoints:
            if ep.mode == "dpdk" and ep.pci_addr is not None:
                dpdk_pci_by_host.setdefault(ep.host, set()).add(ep.pci_addr)
        for ep in self.endpoints:
            if ep.mode in {"probe", "native"} and ep.nic is not None:
                if ep.nic in dpdk_pci_by_host.get(ep.host, set()):
                    raise ValueError(
                        f"endpoint {ep.name!r} has nic={ep.nic!r} which is also "
                        f"bound as a DPDK pci_addr on host {ep.host!r}; "
                        "a NIC cannot be used in both kernel and DPDK modes"
                    )

        return self

    @model_validator(mode="after")
    def _assign_trex_port_ids(self) -> "StagelabConfig":
        """Assign consecutive trex_port_id to DPDK endpoints, per host, in declaration order."""
        by_host: dict[str, int] = {}
        for ep in self.endpoints:
            if ep.mode == "dpdk":
                ep.trex_port_id = by_host.get(ep.host, 0)
                by_host[ep.host] = by_host.get(ep.host, 0) + 1
        return self

    def endpoint_by_name(self, name: str) -> "Endpoint":
        """Return the Endpoint with the given name, or raise KeyError."""
        for ep in self.endpoints:
            if ep.name == name:
                return ep
        raise KeyError(f"endpoint {name!r} not found")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load(path: "str | Path") -> StagelabConfig:
    """Load and validate a stagelab YAML config file."""
    with open(path) as fh:
        data = yaml.safe_load(fh)
    return StagelabConfig.model_validate(data)


def total_hugepages_per_host(cfg: StagelabConfig) -> dict[str, int]:
    """Return sum of hugepages_gib across all DPDK endpoints per host.

    Informational helper for the bootstrap task — no validation is performed.
    Hosts with no DPDK endpoints are omitted from the result.
    """
    totals: dict[str, int] = {}
    for ep in cfg.endpoints:
        if ep.mode == "dpdk":
            totals[ep.host] = totals.get(ep.host, 0) + ep.hugepages_gib
    return totals


def _is_dos_target_allowed(ip_or_cidr: str, allowlist: list[str]) -> bool:
    """True iff ``ip_or_cidr`` is a subnet (or single IP) contained in any
    of the allowlist entries. Empty allowlist → returns False (fail-safe:
    nothing is allowed until explicitly whitelisted)."""
    if not allowlist:
        return False
    try:
        candidate = ipaddress.ip_network(ip_or_cidr, strict=False)
    except ValueError:
        return False
    for allowed in allowlist:
        try:
            parent = ipaddress.ip_network(allowed, strict=False)
        except ValueError:
            continue
        if candidate.version == parent.version and candidate.subnet_of(parent):
            return True
    return False


__all__ = [
    "Host",
    "Dut",
    "Endpoint",
    "ThroughputScenario",
    "ConnStormScenario",
    "RuleScanScenario",
    "TuningSweepScenario",
    "ThroughputDpdkScenario",
    "ConnStormAstfScenario",
    "SynFloodDosScenario",
    "DnsDosScenario",
    "HalfOpenDosScenario",
    "ConntrackOverflowScenario",
    "RuleCoverageMatrixScenario",
    "StatefulHelperFtpScenario",
    "EvasionProbesScenario",
    "ReloadAtomicityScenario",
    "LongFlowSurvivalScenario",
    "HaFailoverDrillScenario",
    "Scenario",
    "PrometheusSourceSpec",
    "SNMPSourceSpec",
    "NftSSHSourceSpec",
    "SourceSpec",
    "MetricsSpec",
    "ReportSpec",
    "StagelabConfig",
    "load",
    "total_hugepages_per_host",
    "_is_dos_target_allowed",
]
