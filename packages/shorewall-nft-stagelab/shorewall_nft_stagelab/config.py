"""Pydantic StagelabConfig: YAML schema for hosts, DUT, endpoints, scenarios."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Annotated, Literal, Union

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_PCI_RE = re.compile(r"^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$")

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
    # --- DPDK-specific ---
    pci_addr: str | None = None            # "0000:01:00.0"
    dpdk_cores: list[int] = []             # CPU cores for DPDK poll mode
    hugepages_gib: int = 0                 # memory footprint
    trex_role: Literal["client", "server", ""] = ""

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


class ConnStormScenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: Literal["conn_storm"]
    source: str
    sink: str
    target_conns: int
    rate_per_s: int
    hold_s: int


class RuleScanScenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: Literal["rule_scan"]
    source: str
    target_subnet: str
    random_count: int


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


Scenario = Annotated[
    Union[ThroughputScenario, ConnStormScenario, RuleScanScenario, TuningSweepScenario],
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


class SNMPSourceSpec(BaseModel):
    kind: Literal["snmp"]
    name: str
    host: str
    community: str
    oids: list[str]
    port: int = 161
    timeout_s: float = 3.0
    model_config = ConfigDict(extra="forbid")


SourceSpec = Annotated[
    Union[PrometheusSourceSpec, SNMPSourceSpec],
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
        for sc in self.scenarios:
            if sc.source not in ep_name_set:
                raise ValueError(
                    f"scenario {sc.id!r} source {sc.source!r} not found in endpoints"
                )
            if hasattr(sc, "sink") and sc.sink not in ep_name_set:  # type: ignore[union-attr]
                raise ValueError(
                    f"scenario {sc.id!r} sink {sc.sink!r} not found in endpoints"
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


__all__ = [
    "Host",
    "Dut",
    "Endpoint",
    "ThroughputScenario",
    "ConnStormScenario",
    "RuleScanScenario",
    "TuningSweepScenario",
    "Scenario",
    "PrometheusSourceSpec",
    "SNMPSourceSpec",
    "SourceSpec",
    "MetricsSpec",
    "ReportSpec",
    "StagelabConfig",
    "load",
    "total_hugepages_per_host",
]
