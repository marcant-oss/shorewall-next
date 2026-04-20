"""Simlab run report writer — persistent archive for later reference.

Every completed simlab run emits a pair of files under
``<repo>/docs/testing/simlab-reports/<UTC-timestamp>/``:

  * ``report.json`` — full structured dump, including every probe
    and its observed verdict. Machine-parseable for later
    regression hunts.
  * ``report.md`` — condensed human-readable summary with per-
    category statistics, sysctl warnings, resource peaks, and a
    top-of-mismatches list. Also includes environment (kernel,
    python, scapy, nft, shorewall-nft versions) so we can correlate
    behaviour changes to software updates.
  * ``mismatches.txt`` — one line per probe whose observed verdict
    did NOT match the expected one. Lets you grep-find a regression
    later.

The writer is deliberately dependency-free: it only uses stdlib
``json``, ``pathlib``, and ``subprocess`` to collect version info.
Absence of a writable report dir → log a warning and continue.
"""

from __future__ import annotations

import json
import platform
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Default archive location: ``docs/testing/simlab-reports`` under the
# repository root. A simlab run on the test VM mounts the repo at
# /root/shorewall-nft so that path also lives on disk there; results
# are rsync'd back to the host by the operator.
DEFAULT_REPORT_DIR = Path(__file__).resolve().parents[3] / \
    "docs" / "testing" / "simlab-reports"


@dataclass
class CategoryStats:
    """Per-category test result counters.

    The four-way split (pass_accept / pass_drop / fail_drop / fail_accept)
    is what matters for regression triage — never just ``mismatch``. See
    ``feedback_test_reports`` in the operator's memory for the rationale.
    """
    name: str
    total: int = 0
    # Four-way pass/fail split
    pass_accept: int = 0   # expected ACCEPT, got ACCEPT  (correct allow)
    pass_drop: int = 0     # expected DROP,   got DROP    (correct block)
    fail_drop: int = 0     # expected ACCEPT, got DROP    (should have had access)
    fail_accept: int = 0   # expected DROP,   got ACCEPT  (shouldn't have had access)
    unknown_expected: int = 0
    errored: int = 0
    latencies_ms: list[int] = field(default_factory=list)

    @property
    def match(self) -> int:
        return self.pass_accept + self.pass_drop

    @property
    def mismatch(self) -> int:
        return self.fail_drop + self.fail_accept

    def summary(self) -> dict[str, Any]:
        from statistics import mean, median, quantiles
        latmin = min(self.latencies_ms) if self.latencies_ms else 0
        latmax = max(self.latencies_ms) if self.latencies_ms else 0
        latavg = int(mean(self.latencies_ms)) if self.latencies_ms else 0
        latp50 = int(median(self.latencies_ms)) if self.latencies_ms else 0
        p99 = 0
        if len(self.latencies_ms) >= 100:
            try:
                p99 = int(quantiles(self.latencies_ms, n=100)[-1])
            except Exception:
                p99 = latmax
        else:
            p99 = latmax
        return {
            "total": self.total,
            "pass_accept": self.pass_accept,
            "pass_drop": self.pass_drop,
            "fail_drop": self.fail_drop,
            "fail_accept": self.fail_accept,
            "match": self.match,
            "mismatch": self.mismatch,
            "unknown_expected": self.unknown_expected,
            "errored": self.errored,
            "latency_ms": {
                "min": latmin, "avg": latavg, "p50": latp50,
                "p99": p99, "max": latmax,
            },
        }


def _env_versions() -> dict[str, str]:
    """Collect env info for the report header."""
    out: dict[str, str] = {}
    out["kernel"] = platform.uname().release
    out["python"] = platform.python_version()
    try:
        r = subprocess.run(["nft", "--version"],
                           capture_output=True, text=True, timeout=2)
        out["nft"] = r.stdout.strip().splitlines()[0] if r.stdout else ""
    except Exception:
        out["nft"] = "n/a"
    try:
        import scapy
        out["scapy"] = scapy.__version__
    except Exception:
        out["scapy"] = "n/a"
    try:
        from shorewall_nft import __version__ as _v
        out["shorewall_nft"] = _v
    except Exception:
        out["shorewall_nft"] = "n/a"
    # Git HEAD if we're running out of a checkout
    try:
        r = subprocess.run(
            ["git", "-C", str(Path(__file__).resolve().parents[3]),
             "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=2,
        )
        out["git_head"] = r.stdout.strip() or "n/a"
    except Exception:
        out["git_head"] = "n/a"
    return out


def _serialise_probe(probe_tuple: tuple) -> dict[str, Any]:
    cat, expected, spec, meta = probe_tuple
    return {
        "category": cat,
        "probe_id": spec.probe_id,
        "inject_iface": spec.inject_iface,
        "expect_iface": spec.expect_iface,
        "expected": expected,
        "observed": spec.verdict,
        "elapsed_ms": spec.elapsed_ms,
        "desc": meta.get("desc", ""),
        "oracle_reason": meta.get("oracle_reason", ""),
    }


def write_report(
    archive_root: Path,
    run_name: str,
    probes: list[tuple],
    timings: dict[str, float],
    peaks: dict[str, Any],
    resource_delta: dict[str, int],
    sysctl_warnings: list[str],
    iface_count: int,
    route_count_v4: int,
    route_count_v6: int,
) -> Path:
    """Write a full report + markdown summary + mismatch list.

    Returns the path to the run directory.
    """
    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y%m%dT%H%M%SZ")
    run_dir = archive_root / ts
    run_dir.mkdir(parents=True, exist_ok=True)

    # Per-category breakdown — four-way pass/fail split.
    cats: dict[str, CategoryStats] = {}
    for cat, expected, spec, _meta in probes:
        cs = cats.setdefault(cat, CategoryStats(name=cat))
        cs.total += 1
        observed = spec.verdict or "NONE"
        if expected == "UNKNOWN":
            cs.unknown_expected += 1
        elif observed == "ACCEPT" and expected == "ACCEPT":
            cs.pass_accept += 1
        elif observed == "DROP" and expected == "DROP":
            cs.pass_drop += 1
        elif observed == "DROP" and expected == "ACCEPT":
            cs.fail_drop += 1
        elif observed == "ACCEPT" and expected == "DROP":
            cs.fail_accept += 1
        else:
            cs.errored += 1
        if spec.elapsed_ms > 0:
            cs.latencies_ms.append(spec.elapsed_ms)

    # JSON report
    report: dict[str, Any] = {
        "timestamp_utc": now.isoformat(),
        "run_name": run_name,
        "env": _env_versions(),
        "topology": {
            "iface_count": iface_count,
            "routes_v4": route_count_v4,
            "routes_v6": route_count_v6,
        },
        "timings": timings,
        "peaks": peaks,
        "resource_delta": resource_delta,
        "sysctl_warnings": sysctl_warnings,
        "categories": {
            name: cs.summary() for name, cs in cats.items()
        },
        "probes": [_serialise_probe(p) for p in probes],
    }
    (run_dir / "report.json").write_text(json.dumps(report, indent=2))

    # Markdown summary
    md: list[str] = []
    md.append(f"# simlab run — {ts}")
    md.append("")
    md.append("## Environment")
    for k, v in report["env"].items():
        md.append(f"- **{k}**: {v}")
    md.append("")
    md.append("## Topology")
    md.append(f"- interfaces: {iface_count}")
    md.append(f"- v4 routes installed: {route_count_v4}")
    md.append(f"- v6 routes installed: {route_count_v6}")
    md.append("")
    md.append("## Timings")
    for k, v in timings.items():
        md.append(f"- {k}: {v:.3f}s")
    md.append("")
    md.append("## Peaks")
    for k, v in peaks.items():
        md.append(f"- {k}: {v}")
    md.append("")
    md.append("## Resource delta (after − before)")
    for k, v in resource_delta.items():
        md.append(f"- {k}: {v:+d}")
    md.append("")
    md.append("## sysctl warnings")
    if sysctl_warnings:
        for w in sysctl_warnings:
            md.append(f"- ⚠ {w}")
    else:
        md.append("- ✓ none")
    md.append("")
    md.append("## Category results")
    md.append("")
    md.append("Columns: **fail_drop** = should have had access but was "
              "DROPPED. **fail_accept** = should have been blocked but was "
              "ACCEPTED. pass_acc/pass_drp are the two correct outcomes.")
    md.append("")
    md.append("| Category | Total | ok | pass_acc | pass_drp | **fail_drop** | "
              "**fail_accept** | unknown | err | avg | p50 | p99 | max |")
    md.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for name in sorted(cats):
        cs = cats[name].summary()
        md.append(
            f"| {name} | {cs['total']} | {cs['match']} "
            f"| {cs['pass_accept']} | {cs['pass_drop']} "
            f"| {cs['fail_drop']} | {cs['fail_accept']} "
            f"| {cs['unknown_expected']} | {cs['errored']} "
            f"| {cs['latency_ms']['avg']}ms | {cs['latency_ms']['p50']}ms "
            f"| {cs['latency_ms']['p99']}ms | {cs['latency_ms']['max']}ms |"
        )
    md.append("")
    (run_dir / "report.md").write_text("\n".join(md) + "\n")

    # Mismatches file — grouped by failure direction so triage doesn't
    # have to re-classify by hand. RANDOM probes carry the oracle's
    # reasoning string (which rule matched, why ACCEPT/DROP was expected)
    # so a reader can decide "oracle wrong" vs "emit wrong" at a glance.
    fail_drop: list[str] = []   # expected ACCEPT, got DROP
    fail_accept: list[str] = [] # expected DROP, got ACCEPT
    errored: list[str] = []
    for cat, expected, spec, meta in probes:
        if expected == "UNKNOWN":
            continue
        if not spec.verdict or spec.verdict == expected:
            continue
        desc = meta.get("desc", "")
        reason = meta.get("oracle_reason", "")
        line = (
            f"{cat:10} [{spec.inject_iface}→{spec.expect_iface}] "
            f"expected={expected} got={spec.verdict} "
            f"[{desc}]"
        )
        if reason:
            line += f"  ↳ oracle: {reason}"
        if expected == "ACCEPT" and spec.verdict == "DROP":
            fail_drop.append(line)
        elif expected == "DROP" and spec.verdict == "ACCEPT":
            fail_accept.append(line)
        else:
            errored.append(line)
    if fail_drop or fail_accept or errored:
        out_lines: list[str] = []
        if fail_drop:
            out_lines.append(
                f"# fail_drop — should have had access but was DROPPED "
                f"({len(fail_drop)})"
            )
            out_lines.extend(fail_drop)
            out_lines.append("")
        if fail_accept:
            out_lines.append(
                f"# fail_accept — should have been blocked but was ACCEPTED "
                f"({len(fail_accept)})"
            )
            out_lines.extend(fail_accept)
            out_lines.append("")
        if errored:
            out_lines.append(f"# errored — no observed verdict ({len(errored)})")
            out_lines.extend(errored)
            out_lines.append("")
        (run_dir / "mismatches.txt").write_text("\n".join(out_lines))

    _write_fail_pcaps(run_dir, probes)
    return run_dir


def write_json(
    probes: list[tuple],
    path: Path,
    *,
    run_name: str = "",
    run_ts: str | None = None,
) -> Path:
    """Write machine-readable simlab.json matching stagelab audit schema.

    ``probes`` is the same ``(cat, expected, spec, meta)`` list passed to
    :func:`write_report`.  The file is always written atomically to *path*
    (overwrites if exists).  Returns *path*.

    Schema version 1.  Failures are capped at 50 entries; full detail lives
    in the report.json / mismatches.txt produced by :func:`write_report`.
    """
    # Compute aggregate counters across all categories.
    pass_accept = pass_drop = fail_accept = fail_drop = 0
    for _cat, expected, spec, _meta in probes:
        observed = spec.verdict or "NONE"
        if expected == "UNKNOWN":
            continue
        if observed == "ACCEPT" and expected == "ACCEPT":
            pass_accept += 1
        elif observed == "DROP" and expected == "DROP":
            pass_drop += 1
        elif observed == "DROP" and expected == "ACCEPT":
            fail_drop += 1
        elif observed == "ACCEPT" and expected == "DROP":
            fail_accept += 1

    total = pass_accept + pass_drop + fail_accept + fail_drop
    mismatch_rate = (fail_accept + fail_drop) / total if total > 0 else 0.0

    # Collect first 50 failures.
    failures: list[dict] = []
    for _cat, expected, spec, meta in probes:
        if expected == "UNKNOWN":
            continue
        observed = spec.verdict or "NONE"
        if observed != expected:
            failures.append({
                "probe_id": spec.probe_id,
                "inject_iface": spec.inject_iface,
                "expect_iface": spec.expect_iface,
                "expected": expected,
                "observed": observed,
                "oracle_reason": meta.get("oracle_reason", ""),
                "desc": meta.get("desc", ""),
            })
            if len(failures) >= 50:
                break

    payload: dict = {
        "schema_version": 1,
        "kind": "simlab-correctness",
        "run_name": run_name,
        "run_ts": run_ts,
        "summary": {
            "fail_accept": fail_accept,
            "fail_drop": fail_drop,
            "mismatch_rate": round(mismatch_rate, 6),
            "pass_accept": pass_accept,
            "pass_drop": pass_drop,
            "total": total,
        },
        "failures": failures,
        "scenarios": [
            {
                "criteria_results": {"fail_accept_is_zero": fail_accept == 0},
                "duration_s": 0.0,
                "kind": "simlab_correctness",
                "ok": fail_accept == 0,
                "raw": {"count": fail_accept},
                "scenario_id": "simlab-fail-accept",
                "source": "simlab",
                "standard_refs": ["cc-iso-15408-fdp-iff-1"],
                "test_id": "simlab-fail-accept",
            },
            {
                "criteria_results": {
                    "fail_drop_within_tolerance": fail_drop <= 2,
                },
                "duration_s": 0.0,
                "kind": "simlab_correctness",
                "ok": fail_drop <= 2,
                "raw": {"count": fail_drop},
                "scenario_id": "simlab-fail-drop",
                "source": "simlab",
                "standard_refs": ["cc-iso-15408-fdp-iff-1"],
                "test_id": "simlab-fail-drop",
            },
        ],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str))
    return path


def _write_fail_pcaps(run_dir: Path, probes: list[tuple]) -> None:
    """Dump one pcap per failed probe into ``run_dir/fail-pcaps/``.

    Each pcap holds the raw bytes that were injected for that probe,
    parsed as a single Ethernet frame (TAP) or bare IP packet (TUN).
    Filenames encode ``<probe_id>-<inject>-<expect>-<direction>.pcap``
    so triage can grep by probe id or by zone pair without opening
    the files.

    Silent on scapy import error — the operator sees a single note
    in the fail-pcaps.txt index instead of an exception.
    """
    fails: list[tuple] = []
    for cat, expected, spec, meta in probes:
        if expected == "UNKNOWN":
            continue
        if spec.verdict and spec.verdict != expected and spec.payload:
            fails.append((cat, expected, spec, meta))
    if not fails:
        return

    pcap_dir = run_dir / "fail-pcaps"
    pcap_dir.mkdir(parents=True, exist_ok=True)
    index_lines: list[str] = [
        f"# {len(fails)} failed probes — one pcap per probe",
        "# format: <probe_id>  <pcap>  expected=<v> got=<v>  "
        "<inject>→<expect>  <desc>",
        "",
    ]

    try:
        import scapy.all as _sc  # type: ignore[import-not-found]
        from scapy.utils import wrpcap as _wrpcap  # type: ignore[import-not-found]
    except ImportError:
        (run_dir / "fail-pcaps.txt").write_text(
            "# scapy not installed — pcap dump skipped\n"
        )
        return

    for cat, expected, spec, meta in fails:
        direction = (
            "fail_drop" if expected == "ACCEPT" else
            "fail_accept" if expected == "DROP" else
            "error"
        )
        fname = (
            f"{spec.probe_id:05d}-{spec.inject_iface}-"
            f"{spec.expect_iface}-{direction}.pcap"
        )
        path = pcap_dir / fname
        try:
            pkt = _sc.Ether(spec.payload)
            _wrpcap(str(path), [pkt])
        except Exception as e:
            index_lines.append(
                f"{spec.probe_id:05d}  (pcap write failed: {e})")
            continue
        index_lines.append(
            f"{spec.probe_id:05d}  fail-pcaps/{fname}  "
            f"expected={expected} got={spec.verdict}  "
            f"{spec.inject_iface}→{spec.expect_iface}  "
            f"{meta.get('desc', '')}"
        )

    (run_dir / "fail-pcaps.txt").write_text("\n".join(index_lines) + "\n")
