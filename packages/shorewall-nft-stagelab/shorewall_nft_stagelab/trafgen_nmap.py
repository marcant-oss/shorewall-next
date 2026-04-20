"""nmap wrapper: scan-probe generation for rule-coverage validation."""
from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass


@dataclass(frozen=True)
class NmapSpec:
    target: str              # host or CIDR, e.g. "10.0.20.0/24" or "185.x.y.100"
    ports: str = "1-1024"    # nmap -p string
    proto: str = "tcp"       # "tcp" | "udp" | "both"
    source_ip: str = ""      # optional -S
    timing: int = 3          # -T0..-T5
    extra_args: tuple[str, ...] = ()


@dataclass(frozen=True)
class PortResult:
    port: int
    proto: str               # "tcp" | "udp"
    state: str               # "open" | "closed" | "filtered" | "open|filtered" | ...
    service: str             # "" if unknown


@dataclass(frozen=True)
class NmapResult:
    tool: str                # "nmap"
    ok: bool
    target: str
    ports: tuple[PortResult, ...]
    raw_xml: str             # full nmap XML


def build_argv(spec: NmapSpec) -> list[str]:
    """Translate NmapSpec to nmap argv. Always includes `-oX -` (XML to stdout)
    and `-Pn` (skip host discovery)."""
    argv = ["nmap", "-oX", "-", "-Pn", f"-T{spec.timing}", "-p", spec.ports]

    if spec.proto == "tcp":
        argv.append("-sS")
    elif spec.proto == "udp":
        argv.append("-sU")
    else:  # "both"
        argv += ["-sS", "-sU"]

    if spec.source_ip:
        argv += ["-S", spec.source_ip]

    argv.append(spec.target)
    argv.extend(spec.extra_args)
    return argv


def run_nmap(spec: NmapSpec, timeout_s: int | None = None) -> NmapResult:
    """Execute nmap, capture XML stdout, parse. Propagate subprocess errors
    as RuntimeError with stderr excerpt. Timeout → raise."""
    argv = build_argv(spec)
    result = subprocess.run(
        argv,
        check=False,
        text=True,
        capture_output=True,
        timeout=timeout_s,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"nmap exited with rc={result.returncode}: {result.stderr[:500]}"
        )
    if not result.stdout or not result.stdout.strip():
        raise RuntimeError("nmap produced no output")
    return parse_xml(result.stdout, spec.target)


def parse_xml(xml: str, target: str) -> NmapResult:
    """Parse nmap XML (xml.etree.ElementTree) into NmapResult.

    Traverse /nmaprun/host/ports/port elements. Each port yields a
    PortResult. ok=True iff the root has at least one <host> element.
    """
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise RuntimeError(f"nmap XML parse error: {exc}") from exc

    hosts = root.findall("host")
    if not hosts:
        return NmapResult(tool="nmap", ok=False, target=target, ports=(), raw_xml=xml)

    port_results: list[PortResult] = []
    for host in hosts:
        ports_elem = host.find("ports")
        if ports_elem is None:
            continue
        for port_elem in ports_elem.findall("port"):
            portid = int(port_elem.get("portid", 0))
            proto = port_elem.get("protocol", "tcp")
            state_elem = port_elem.find("state")
            state = state_elem.get("state", "") if state_elem is not None else ""
            service_elem = port_elem.find("service")
            service = (
                service_elem.get("name", "") if service_elem is not None else ""
            )
            port_results.append(
                PortResult(port=portid, proto=proto, state=state, service=service)
            )

    return NmapResult(
        tool="nmap",
        ok=True,
        target=target,
        ports=tuple(port_results),
        raw_xml=xml,
    )
