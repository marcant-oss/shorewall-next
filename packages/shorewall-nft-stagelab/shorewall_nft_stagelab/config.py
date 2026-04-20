"""Pydantic StagelabConfig: YAML schema for hosts, DUT, endpoints, scenarios."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Annotated, Literal, Union

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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
    mode: Literal["probe", "native"]
    nic: str | None = None
    vlan: int | None = None
    ipv4: str | None = None
    ipv4_gw: str | None = None
    ipv6: str | None = None
    ipv6_gw: str | None = None
    rss_queues: int | None = None
    irq_affinity: list[int] = []
    bridge: str | None = None

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


Scenario = Annotated[
    Union[ThroughputScenario, ConnStormScenario, RuleScanScenario],
    Field(discriminator="kind"),
]


# ---------------------------------------------------------------------------
# MetricsSpec
# ---------------------------------------------------------------------------

_MetricName = Literal["nft_counters", "conntrack_stats", "nic_ethtool", "cpu_softirq"]


class MetricsSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    poll_interval_s: int = 1
    collect: list[_MetricName] = []


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
            else:
                native_nics.add(key)
        overlap = probe_nics & native_nics
        if overlap:
            host, nic = next(iter(overlap))
            raise ValueError(
                f"NIC {nic!r} on host {host!r} is used by both probe and native endpoints"
            )

        # 7. Probe endpoints must set bridge; native endpoints must NOT set bridge
        #    Native endpoints must set nic + vlan + ipv4
        for ep in self.endpoints:
            if ep.mode == "probe":
                if ep.bridge is None:
                    raise ValueError(
                        f"probe endpoint {ep.name!r} must set 'bridge'"
                    )
            else:  # native
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

        return self


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load(path: "str | Path") -> StagelabConfig:
    """Load and validate a stagelab YAML config file."""
    with open(path) as fh:
        data = yaml.safe_load(fh)
    return StagelabConfig.model_validate(data)


__all__ = [
    "Host",
    "Dut",
    "Endpoint",
    "ThroughputScenario",
    "ConnStormScenario",
    "RuleScanScenario",
    "Scenario",
    "MetricsSpec",
    "ReportSpec",
    "StagelabConfig",
    "load",
]
