#!/usr/bin/env python3
"""Merge per-standard security-test-plan YAML fragments into a canonical file.

Usage:
    tools/merge-security-test-plan-yaml.py [--out PATH]

Reads all docs/testing/security-test-plan.<std>.yaml fragments (excluding the
output file itself) and writes a merged canonical YAML to --out (default:
docs/testing/security-test-plan.yaml).

The script fails with a clear error if any test_id appears in more than one
fragment.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ModuleNotFoundError:
    sys.exit("ERROR: pyyaml is not installed. Run: pip install pyyaml")

# ---------------------------------------------------------------------------
# Standard metadata (determines ordering in the merged output)
# ---------------------------------------------------------------------------

_STANDARD_META = [
    {
        "id": "cc-iso-15408",
        "title": "Common Criteria (ISO/IEC 15408)",
        "fragment_owner": "b1",
        "fragment_file": "security-test-plan.cc.yaml",
        "nist_fragment": "security-test-plan.nist.yaml",
    },
    {
        "id": "nist-800-53",
        "title": "NIST SP 800-53 rev 5",
        "fragment_owner": "b1",
        "fragment_file": "security-test-plan.nist.yaml",
    },
    {
        "id": "bsi-grundschutz",
        "title": "BSI IT-Grundschutz",
        "fragment_owner": "b2",
        "fragment_file": "security-test-plan.bsi.yaml",
    },
    {
        "id": "cis-benchmarks",
        "title": "CIS Benchmarks",
        "fragment_owner": "b2",
        "fragment_file": "security-test-plan.cis.yaml",
    },
    {
        "id": "owasp",
        "title": "OWASP Firewall Testing",
        "fragment_owner": "b3",
        "fragment_file": "security-test-plan.owasp.yaml",
    },
    {
        "id": "iso-27001",
        "title": "ISO/IEC 27001 Annex A / 27002",
        "fragment_owner": "b3",
        "fragment_file": "security-test-plan.iso27001.yaml",
    },
    {
        "id": "performance-ipv6",
        "title": "IPv6 throughput parity (performance addendum)",
        "fragment_owner": "c3",
        "fragment_file": "security-test-plan.ipv6-perf.yaml",
    },
]

# Mapping from fragment `standard:` field to canonical standard id
_STANDARD_FIELD_MAP = {
    "cc-iso-15408": "cc-iso-15408",
    "nist-800-53": "nist-800-53",
    "bsi-grundschutz": "bsi-grundschutz",
    "cis-benchmarks": "cis-benchmarks",
    "owasp": "owasp",
    "iso-27001": "iso-27001",
    "performance-ipv6": "performance-ipv6",
}


def _load_fragment(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    try:
        return yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        sys.exit(f"ERROR: cannot parse {path}: {exc}")


def _infer_standard_id(fragment: dict, fragment_path: Path) -> str:
    """Determine canonical standard id from a fragment dict."""
    # Try top-level 'standard' or 'meta.standard' field
    std = fragment.get("standard") or (fragment.get("meta") or {}).get("standard")
    if std and std in _STANDARD_FIELD_MAP:
        return _STANDARD_FIELD_MAP[std]
    # Fall back to filename
    stem = fragment_path.stem  # e.g. "security-test-plan.cc"
    suffix = stem.split(".", 1)[-1]  # e.g. "cc"
    file_to_std = {
        "cc": "cc-iso-15408",
        "nist": "nist-800-53",
        "bsi": "bsi-grundschutz",
        "cis": "cis-benchmarks",
        "owasp": "owasp",
        "iso27001": "iso-27001",
        "ipv6-perf": "performance-ipv6",
    }
    if suffix in file_to_std:
        return file_to_std[suffix]
    sys.exit(f"ERROR: cannot determine standard id for fragment {fragment_path}")


def merge(catalogue_dir: Path, out_path: Path) -> None:
    out_path_abs = out_path.resolve()

    all_tests: list[dict] = []
    all_out_of_scope: list[dict] = []
    seen_test_ids: dict[str, str] = {}  # test_id -> fragment filename

    # Ordered pass over known standards
    for meta in _STANDARD_META:
        fpath = catalogue_dir / meta["fragment_file"]
        if not fpath.exists():
            print(f"WARNING: fragment not found: {fpath}", file=sys.stderr)
            continue

        fragment = _load_fragment(fpath)
        std_id = meta["id"]

        # Tests
        for entry in fragment.get("tests", []):
            tid = entry.get("test_id")
            if not tid:
                print(
                    f"WARNING: entry without test_id in {fpath.name}; skipping",
                    file=sys.stderr,
                )
                continue
            if tid in seen_test_ids:
                sys.exit(
                    f"ERROR: duplicate test_id {tid!r} in {fpath.name} "
                    f"(first seen in {seen_test_ids[tid]})"
                )
            seen_test_ids[tid] = fpath.name

            merged_entry: dict = {"test_id": tid, "standard": std_id}
            for k, v in entry.items():
                if k != "test_id":
                    merged_entry[k] = v
            all_tests.append(merged_entry)

        # Out-of-scope items
        for item in fragment.get("out_of_scope", []):
            oos: dict = {"standard": std_id}
            oos.update(item)
            all_out_of_scope.append(oos)

    # Build output document
    standards_list = [
        {"id": m["id"], "title": m["title"], "fragment_owner": m["fragment_owner"]}
        for m in _STANDARD_META
    ]

    doc = {
        "__comment__": (
            "Auto-generated (security-test-plan) — DO NOT edit by hand; "
            "regenerate via tools/merge-security-test-plan-yaml.py or the M1 merger."
        ),
        "schema_version": 1,
        "generated_by": "M1 merger (security-test-plan feature)",
        "generated_at": datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
        "standards": standards_list,
        "tests": all_tests,
        "out_of_scope": all_out_of_scope,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        yaml.dump(doc, default_flow_style=False, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    print(
        f"Wrote {len(all_tests)} tests, {len(all_out_of_scope)} out-of-scope items "
        f"-> {out_path}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Merge per-standard YAML fragments into security-test-plan.yaml"
    )
    parser.add_argument(
        "--out",
        metavar="PATH",
        default=None,
        help="Output path (default: docs/testing/security-test-plan.yaml relative to repo root)",
    )
    parser.add_argument(
        "--catalogue-dir",
        metavar="DIR",
        default=None,
        help="Directory containing the fragment files (default: docs/testing/ relative to repo root)",
    )
    args = parser.parse_args()

    # Locate repo root relative to this script (tools/)
    repo_root = Path(__file__).resolve().parent.parent

    catalogue_dir = Path(args.catalogue_dir) if args.catalogue_dir else repo_root / "docs" / "testing"
    out_path = Path(args.out) if args.out else catalogue_dir / "security-test-plan.yaml"

    merge(catalogue_dir, out_path)


if __name__ == "__main__":
    main()
