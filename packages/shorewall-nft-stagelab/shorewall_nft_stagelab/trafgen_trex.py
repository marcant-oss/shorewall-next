"""TRex wrapper: Stateless (STL) and Advanced Stateful (ASTF) traffic generation."""

from __future__ import annotations

import os
import tempfile
import time
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Spec dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TrexStatelessSpec:
    ports: tuple[int, ...]           # e.g. (0, 1) — TRex logical port ids
    duration_s: int = 10
    multiplier: str = "10gbps"       # "50%", "1000kpps", "5gbps", etc.
    pcap_files: tuple[str, ...] = () # optional .pcap replay files, one per port
    profile_py: str = ""             # path to STL profile .py
    profile_text: str = ""           # inline profile source; priority over profile_py
    trex_daemon_port: int = 4501     # STL RPC port
    trex_host: str = "127.0.0.1"


@dataclass(frozen=True)
class TrexAstfSpec:
    profile_py: str = ""             # path to ASTF profile .py
    profile_text: str = ""           # inline profile source; priority over profile_py
    duration_s: int = 30
    multiplier: float = 1.0          # scales base CPS in profile
    trex_daemon_port: int = 4502     # ASTF RPC port
    trex_host: str = "127.0.0.1"


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TrexResult:
    """Normalized summary. DPDK-specific fields beyond generic TrafGenResult."""
    tool: str                    # "trex-stl" | "trex-astf"
    ok: bool
    duration_s: float
    throughput_gbps: float
    pps: float                   # packets per second (aggregate)
    concurrent_sessions: int     # ASTF only — 0 for STL
    new_sessions_per_s: float    # ASTF only — 0 for STL
    errors: int                  # drops + RPC errors
    raw: dict = field(compare=False)  # full TRex stats dict


# ---------------------------------------------------------------------------
# Lazy imports
# ---------------------------------------------------------------------------

def _import_stl() -> object:
    """Lazy import of trex_stl_lib. Raises ImportError with guidance."""
    try:
        import trex_stl_lib.api as _api  # type: ignore[import]
        return _api
    except ImportError as exc:
        raise ImportError(
            "trex_stl_lib not found. Install TRex and run: "
            "stagelab bootstrap --role stagelab-agent-dpdk"
        ) from exc


def _import_astf() -> object:
    """Lazy import of trex.astf.api. Raises ImportError with guidance."""
    try:
        import trex.astf.api as _api  # type: ignore[import]
        return _api
    except ImportError as exc:
        raise ImportError(
            "trex.astf.api not found. Install TRex and run: "
            "stagelab bootstrap --role stagelab-agent-dpdk"
        ) from exc


# ---------------------------------------------------------------------------
# Pure parsers
# ---------------------------------------------------------------------------

def parse_stl_stats(stats: dict, duration_s: float) -> TrexResult:
    """Parse STLClient.get_stats() dict into TrexResult.

    Extracts:
      global.total_tx_bps  → throughput_gbps
      global.total_tx_pps  → pps
      global.err_counters  → errors (sum of all counter values)
    ok=True if errors == 0.
    """
    g = stats.get("global", {})
    throughput_gbps = float(g.get("total_tx_bps", 0.0)) / 1e9
    pps = float(g.get("total_tx_pps", 0.0))

    err_counters = g.get("err_counters", {})
    if isinstance(err_counters, dict):
        errors = sum(int(v) for v in err_counters.values())
    else:
        errors = int(err_counters)

    return TrexResult(
        tool="trex-stl",
        ok=(errors == 0),
        duration_s=duration_s,
        throughput_gbps=throughput_gbps,
        pps=pps,
        concurrent_sessions=0,
        new_sessions_per_s=0.0,
        errors=errors,
        raw=stats,
    )


def parse_astf_stats(stats: dict, duration_s: float) -> TrexResult:
    """Parse ASTF stats dict into TrexResult.

    Extracts from global:
      m_active_flows       → concurrent_sessions
      m_est_flows_ps       → new_sessions_per_s
      m_tx_bps             → throughput_gbps
      m_tx_pps             → pps
      m_tx_drop + m_rx_drop → errors
    ok=True if errors == 0.
    """
    g = stats.get("global", {})
    throughput_gbps = float(g.get("m_tx_bps", 0.0)) / 1e9
    pps = float(g.get("m_tx_pps", 0.0))
    concurrent_sessions = int(g.get("m_active_flows", 0))
    new_sessions_per_s = float(g.get("m_est_flows_ps", 0.0))
    errors = int(g.get("m_tx_drop", 0)) + int(g.get("m_rx_drop", 0))

    return TrexResult(
        tool="trex-astf",
        ok=(errors == 0),
        duration_s=duration_s,
        throughput_gbps=throughput_gbps,
        pps=pps,
        concurrent_sessions=concurrent_sessions,
        new_sessions_per_s=new_sessions_per_s,
        errors=errors,
        raw=stats,
    )


# ---------------------------------------------------------------------------
# Run functions
# ---------------------------------------------------------------------------

def run_trex_stl(spec: TrexStatelessSpec) -> TrexResult:
    """Connect via STLClient, upload streams, start, wait, stop, return stats.

    Raises ImportError (with guidance) if trex_stl_lib not importable.
    Raises RuntimeError on TRex RPC errors.
    """
    api = _import_stl()

    client = api.STLClient(
        server=spec.trex_host,
        sync_port=spec.trex_daemon_port,
    )
    _tmp_profile: str | None = None
    try:
        client.connect()
        client.reset(ports=list(spec.ports))

        if spec.profile_text:
            fd, _tmp_profile = tempfile.mkstemp(suffix=".py")
            os.write(fd, spec.profile_text.encode())
            os.close(fd)
            profile_path = _tmp_profile
        elif spec.profile_py:
            profile_path = spec.profile_py
        else:
            profile_path = None

        if profile_path:
            profile = api.STLProfile.load(profile_path)
            streams = profile.get_streams()
            for port in spec.ports:
                client.add_streams(streams, ports=[port])
        elif spec.pcap_files:
            for port, pcap in zip(spec.ports, spec.pcap_files):
                stream = api.STLStream(
                    packet=api.STLPktBuilder(pkt_buffer=open(pcap, "rb").read()),
                )
                client.add_streams(stream, ports=[port])

        client.start(
            ports=list(spec.ports),
            mult=spec.multiplier,
            duration=spec.duration_s,
        )
        time.sleep(spec.duration_s)
        client.stop(ports=list(spec.ports))
        client.wait_on_traffic(ports=list(spec.ports))

        stats = client.get_stats()
    except ImportError:
        raise
    except Exception as exc:
        raise RuntimeError(f"TRex STL error: {exc}") from exc
    finally:
        try:
            client.disconnect()
        except Exception:
            pass
        if _tmp_profile is not None:
            try:
                os.unlink(_tmp_profile)
            except OSError:
                pass

    return parse_stl_stats(stats, float(spec.duration_s))


def run_trex_astf(spec: TrexAstfSpec) -> TrexResult:
    """Connect via ASTFClient, load profile, start, wait, stop, return stats.

    Raises ImportError (with guidance) if trex.astf.api not importable.
    Raises RuntimeError on TRex RPC errors.
    """
    api = _import_astf()

    client = api.ASTFClient(
        server=spec.trex_host,
        sync_port=spec.trex_daemon_port,
    )
    _tmp_profile: str | None = None
    try:
        client.connect()
        client.reset()

        if spec.profile_text:
            fd, _tmp_profile = tempfile.mkstemp(suffix=".py")
            os.write(fd, spec.profile_text.encode())
            os.close(fd)
            profile_path = _tmp_profile
        elif spec.profile_py:
            profile_path = spec.profile_py
        else:
            raise ValueError("TrexAstfSpec: either profile_text or profile_py must be set")

        profile = api.ASTFProfile.load(profile_path)
        client.load_profile(profile)

        client.start(mult=spec.multiplier, duration=spec.duration_s)
        time.sleep(spec.duration_s)
        client.stop()
        client.wait_on_traffic()

        stats = client.get_stats()
    except ImportError:
        raise
    except Exception as exc:
        raise RuntimeError(f"TRex ASTF error: {exc}") from exc
    finally:
        try:
            client.disconnect()
        except Exception:
            pass
        if _tmp_profile is not None:
            try:
                os.unlink(_tmp_profile)
            except OSError:
                pass

    return parse_astf_stats(stats, float(spec.duration_s))
